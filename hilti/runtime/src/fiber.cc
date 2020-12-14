// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.


#ifdef _FORTIFY_SOURCE
// Disable in this file, the longjmps can cause false positives.
//
// TODO: Do we still need this?
#undef _FORTIFY_SOURCE
#endif

#include <fiber/fiber.h>

#include <memory>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/context.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

#ifdef HILTI_HAVE_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

// Define to activate stack sharing, undefine to use of individual per-fiber
// stacks.
//
// TODO: Unclear if we want to keep this like this. Could make a runtime
// option, or could remove choice completely.
#define USE_SHARED_STACK

using namespace hilti::rt;

const void* _main_thread_bottom = nullptr;
std::size_t _main_thread_size = 0;

extern "C" {

// A dummy fallback function which will be put on the bottom of all fibers'
// call stacks. This function should never execute.
[[noreturn]] static void fiber_bottom_abort(Fiber* fiber, void* args) { abort(); }

void detail::_Trampoline(void* argsp) {
    auto fiber = *reinterpret_cast<detail::Fiber**>(argsp);
    fiber->_finishSwitchFiber("trampoline-init");

    HILTI_RT_DEBUG("fibers", fmt("[%p] entering trampoline loop", fiber));

    // Via recycling a fiber can run an arbitrary number of user jobs. So
    // this trampoline is really a loop that yields after it has finished its
    // function, and expects a new run function once it's resumed.
    ++detail::Fiber::_initialized;

    while ( true ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] new iteration of trampoline loop", fiber));

        assert(fiber->_state == detail::Fiber::State::Running);

        try {
            fiber->_result = (*fiber->_function)(fiber);
        } catch ( ... ) {
            HILTI_RT_DEBUG("fibers", fmt("[%p] got exception, forwarding", fiber));
            fiber->_exception = std::current_exception();
        }

        fiber->_function = {};
        fiber->_state = detail::Fiber::State::Idle;
        detail::Fiber::_switchTo(fiber->_caller);
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] finished trampoline loop", fiber));
}
}

detail::FiberContext::FiberContext() {
    main = std::make_unique<detail::Fiber>(true);
    current = main.get();

    switch_trampoline = std::make_unique<::Fiber>();
    if ( ! ::fiber_alloc(switch_trampoline.get(), IndividualStackSize, fiber_bottom_abort, this,
                         FIBER_FLAG_GUARD_LO | FIBER_FLAG_GUARD_HI) )
        throw RuntimeError("could not allocate fiber switch trampoline");

#ifdef USE_SHARED_STACK
    // Instantiate an unused fiber just to create the shared stack.
    shared_stack = std::make_unique<::Fiber>();
    if ( ! ::fiber_alloc(shared_stack.get(), SharedStackSize, fiber_bottom_abort, this,
                         FIBER_FLAG_GUARD_LO | FIBER_FLAG_GUARD_HI) )
        throw RuntimeError("could not allocate shared stack");
#endif
}

detail::FiberContext::~FiberContext() {}

detail::Fiber::Fiber(bool is_main_fiber) : _is_main(is_main_fiber), _fiber(std::make_unique<::Fiber>()) {
    HILTI_RT_DEBUG("fibers", fmt("[%p] allocated new fiber", this));

    if ( is_main_fiber ) {
        ::fiber_init_toplevel(_fiber.get());
        _caller = nullptr;
    }
    else {
#ifdef USE_SHARED_STACK
        auto shared_stack = context::detail::get()->fiber.shared_stack.get();
        auto alloc =
            ::fiber_init(_fiber.get(), shared_stack->stack, shared_stack->stack_size, fiber_bottom_abort, this);
#else
        auto alloc = ::fiber_alloc(_fiber.get(), FiberContext::IndividualStackSize, fiber_bottom_abort, this,
                                   FIBER_FLAG_GUARD_LO | FIBER_FLAG_GUARD_HI);
#endif
        if ( ! alloc )
            internalError("could not allocate fiber");

        _caller = context::detail::get()->fiber.current;
    }

    ++_total_fibers;
    ++_current_fibers;

    if ( _current_fibers > _max_fibers )
        _max_fibers = _current_fibers;
}

class AbortException : public std::exception {};

detail::Fiber::~Fiber() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] deleting fiber", this));
    // TODO: We can't reuse a destroyed fiber currently, it'll tell us it's
    // not executing. Need to fix.
    // ::fiber_destroy(_fiber.get());
    --_current_fibers;
}

detail::StackRegion::StackRegion(const ::Fiber* fiber) {
    // TODO: In theory this is in platform-specific. We assume the stack is
    // growing downwards.
    lower = reinterpret_cast<char*>(fiber->regs.sp);
    upper = reinterpret_cast<char*>(fiber->regs.sp) + fiber_stack_used_size(fiber);
}

// Captures arguments passed into stack switcher trampoline.
struct SwitchArgs {
    ::Fiber* switcher = nullptr;
    detail::Fiber* from = nullptr;
    detail::Fiber* to = nullptr;
};

// Entry point for stack switch trampoline.
extern "C" void execute_fiber_switch(void* args0) {
    auto* args = reinterpret_cast<SwitchArgs*>(args0);
    auto from = args->from;
    auto to = args->to;

    auto from_tag = (from->isMain() ? "main" : "fiber");
    auto to_tag = (to->isMain() ? "main" : "fiber");
    HILTI_RT_DEBUG("fibers", fmt("[stack-switcher] switching from %s-%p to %s-%p", from_tag, from, to_tag, to));

    auto* context = context::detail::get();
    assert(context->fiber.current == nullptr);
    context->fiber.current = to;

#ifdef USE_SHARED_STACK
    if ( ! from->isMain() ) {
        // Copy old stack out.
        from->saved_stack.region = detail::StackRegion(from->_fiber.get());
        from->saved_stack.buffer = ::realloc(from->saved_stack.buffer, from->saved_stack.region.size());
        if ( ! from->saved_stack.buffer )
            throw RuntimeError("out of memory when saving fiber stack");

        HILTI_RT_DEBUG("fibers", fmt("[stack-switcher] saving stack %s to %p", from->saved_stack.region,
                                     from->saved_stack.buffer));
        ::memcpy(from->saved_stack.buffer, from->saved_stack.region.lower, from->saved_stack.region.size());
    }

    if ( ! to->isMain() && to->saved_stack.buffer ) {
        // Copy new stack in.
        HILTI_RT_DEBUG("fibers", fmt("[stack-switcher] restoring stack %s from %p", to->saved_stack.region,
                                     to->saved_stack.buffer));
        ::memcpy(to->saved_stack.region.lower, to->saved_stack.buffer, to->saved_stack.region.size());
    }
#endif

    ::fiber_switch(args->switcher, to->_fiber.get());
}

void detail::Fiber::_switchTo(detail::Fiber* to) {
    _startSwitchFiber("run", to->_fiber->stack, to->_fiber->stack_size);

    auto* context = context::detail::get();
    auto* current_fiber = context->fiber.current;
    auto* stack_switcher = context->fiber.switch_trampoline.get();
    assert(current_fiber != to);

    context->fiber.current = nullptr;

    SwitchArgs args;
    args.switcher = stack_switcher;
    args.from = current_fiber;
    args.to = to;
    ::fiber_push_return(stack_switcher, execute_fiber_switch, &args, sizeof(args));
    ::fiber_switch(current_fiber->_fiber.get(), stack_switcher);

    _finishSwitchFiber("run");
}

void detail::Fiber::run() {
    auto init = (_state == State::Init);

    if ( _state != State::Aborting )
        _state = State::Running;

    if ( init ) {
        detail::Fiber** args;
        ::fiber_reserve_return(_fiber.get(), _Trampoline, reinterpret_cast<void**>(&args), sizeof *args);
        *args = this;
    }

    _caller = context::detail::get()->fiber.current;
    _switchTo(this);

    switch ( _state ) {
        case State::Yielded:
        case State::Idle: return;

        default: internalError("fiber: unexpected case");
    }
}

void detail::Fiber::yield() {
    assert(_state == State::Running);

    _state = State::Yielded;
    _switchTo(_caller);

    if ( _state == State::Aborting )
        throw AbortException();
}

void detail::Fiber::resume() {
    assert(_state == State::Yielded);
    return run();
}

void detail::Fiber::abort() {
    assert(_state == State::Yielded);
    _state = State::Aborting;
    return run();
}

std::unique_ptr<detail::Fiber> detail::Fiber::create() {
    if ( ! context::detail::get()->fiber.cache.empty() ) {
        auto& cache = context::detail::get()->fiber.cache;
        auto f = std::move(cache.back());
        cache.pop_back();
        HILTI_RT_DEBUG("fibers", fmt("[%p] reusing fiber from cache", f.get()));
        return f;
    }

    return std::make_unique<Fiber>();
}

void detail::Fiber::destroy(std::unique_ptr<detail::Fiber> f) {
    if ( f->_state == State::Yielded )
        f->abort();

    auto& cache = context::detail::get()->fiber.cache;
    if ( cache.size() < FiberContext::CacheSize ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] putting fiber back into cache", f.get()));
        cache.push_back(std::move(f));
        return;
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] cache size exceeded, deleting finished fiber", f.get()));
}

void detail::Fiber::primeCache() {
    std::vector<std::unique_ptr<Fiber>> fibers;
    fibers.reserve(FiberContext::CacheSize);

    for ( unsigned int i = 0; i < FiberContext::CacheSize; i++ )
        fibers.emplace_back(Fiber::create());

    while ( fibers.size() ) {
        // TODO: We can't reuse a destroyed fiber currently, it'll tell use
        // it's not executing. Need to fix.
        // Fiber::destroy(std::move(fibers.back()));
        fibers.pop_back();
    }
}

void detail::Fiber::reset() {
    context::detail::get()->fiber.cache.clear();
    _total_fibers = 0;
    _current_fibers = 0;
    _max_fibers = 0;
    _initialized = 0;
}

void detail::Fiber::_startSwitchFiber(const char* tag, const void* stack_bottom, size_t stack_size) {
#ifdef HILTI_HAVE_SANITIZER
    if ( ! stack_bottom ) {
        stack_bottom = _asan.prev_bottom;
        stack_size = _asan.prev_size;
    }

    HILTI_RT_DEBUG("fibers",
                   fmt("[%p/%s/asan] start_switch_fiber %p/%p (fake_stack=%p)", context::detail::get()->fiber.current,
                       tag, stack_bottom, stack_size, &_asan.fake_stack));
    __sanitizer_start_switch_fiber(&_asan.fake_stack, stack_bottom, stack_size);
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] start_switch_fiber in %s", context::detail::get()->fiber.current, tag));
#endif
}

void detail::Fiber::_finishSwitchFiber(const char* tag) {
#ifdef HILTI_HAVE_SANITIZER
    __sanitizer_finish_switch_fiber(_asan.fake_stack, &_asan.prev_bottom, &_asan.prev_size);
    HILTI_RT_DEBUG("fibers",
                   fmt("[%p/%s/asan] finish_switch_fiber %p/%p (fake_stack=%p)", context::detail::get()->fiber.current,
                       tag, _asan.prev_bottom, _asan.prev_size, _asan.fake_stack));
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] finish_switch_fiber in %s", context::detail::get()->fiber.current, tag));
#endif
}

void Resumable::run() {
    checkFiber("run");

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->run();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::resume() {
    checkFiber("resume");

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->resume();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::abort() {
    if ( ! _fiber )
        return;

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->abort();
    context::detail::get()->resumable = old;

    _result.reset();
    _done = true;
}

void Resumable::yielded() {
    if ( auto e = _fiber->exception() ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] rethrowing exception after fiber yielded", _fiber.get()));

        _done = true;
        _result.reset(); // just make sure optional is unset.
        detail::Fiber::destroy(std::move(_fiber));
        _fiber = nullptr;
        std::rethrow_exception(e);
        return;
    }

    if ( _fiber->isDone() ) {
        _done = true;
        _result = _fiber->result(); // might be unset
        detail::Fiber::destroy(std::move(_fiber));
        _fiber = nullptr;
        return;
    }
}

void detail::yield() {
    auto r = context::detail::get()->resumable;

    if ( ! r )
        throw RuntimeError("'yield' in non-suspendable context");

    r->yield();
    context::detail::get()->resumable = r;
}

detail::Fiber::Statistics detail::Fiber::statistics() {
    Statistics stats{
        .total = _total_fibers,
        .current = _current_fibers,
        .cached = context::detail::get()->fiber.cache.size(), // TODO: track globally
        .max = _max_fibers,
        .initialized = _initialized,
    };

    return stats;
}
