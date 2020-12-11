// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#ifdef _FORTIFY_SOURCE
// Disable in this file, the longjmps can cause false positives.
#undef _FORTIFY_SOURCE
#endif

#include <fiber/fiber.h>

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

using namespace hilti::rt;

const void* _main_thread_bottom = nullptr;
std::size_t _main_thread_size = 0;

extern "C" {

// A dummy function which will be put on the bottom of each fiber's call stack. This function should never execute.
[[noreturn]] static void fiber_bottom(Fiber* fiber, void* args) { abort(); }

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

detail::Fiber::Fiber(bool is_main_fiber) : _is_main(is_main_fiber), _fiber(std::make_unique<::Fiber>()) {
    HILTI_RT_DEBUG("fibers", fmt("[%p] allocated new fiber", this));

    if ( is_main_fiber ) {
        ::fiber_init_toplevel(_fiber.get());
        _caller = nullptr;
    }
    else {
        auto shared_stack = context::detail::get()->shared_stack;
        auto alloc =
            ::fiber_init(_fiber.get(), shared_stack->stack, shared_stack->stack_size, fiber_bottom, this);
        if ( ! alloc )
            internalError("could not allocate fiber");

        _caller = context::detail::get()->current_fiber;
    }

    ++_total_fibers;
    ++_current_fibers;

    if ( _current_fibers > _max_fibers )
        _max_fibers = _current_fibers;
}

class AbortException : public std::exception {};

detail::Fiber::~Fiber() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] deleting fiber", this));

    // ::fiber_destroy(_fiber.get()); TODO
    --_current_fibers;
}

void detail::Fiber::_switchTo(detail::Fiber* to) {
    _startSwitchFiber("run", to->_fiber->stack, to->_fiber->stack_size);

    auto* context = context::detail::get();
    assert(context->current_fiber != to);

    auto current_fiber = context->current_fiber;
    assert(current_fiber != to);
    context->current_fiber = to;

    if ( ! current_fiber->isMain() ) {
        // Copy old stack out.
        current_fiber->saved_stack.size = ::fiber_stack_used_size(current_fiber->_fiber.get());
        current_fiber->saved_stack.base = ::realloc(current_fiber->saved_stack.base, current_fiber->saved_stack.size);
        HILTI_RT_DEBUG("fibers", fmt("[%p/from] copy out %p/%llu to %p", current_fiber, ::fiber_stack(current_fiber->_fiber.get()), current_fiber->saved_stack.size, current_fiber->saved_stack.base));
        ::memcpy(current_fiber->saved_stack.base, ::fiber_stack(current_fiber->_fiber.get()), current_fiber->saved_stack.size);
    }

    if ( ! to->isMain() && to->saved_stack.base ) {
        // Copy new stack in.
        HILTI_RT_DEBUG("fibers", fmt("[%p/to  ] copy in %p/%llu to %p", to, to->saved_stack.base, to->saved_stack.size, to->saved_stack.base));
        ::memcpy(::fiber_stack(to->_fiber.get()), to->saved_stack.base, to->saved_stack.size);
    }

    ::fiber_switch(current_fiber->_fiber.get(), to->_fiber.get());

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

    _caller = context::detail::get()->current_fiber; // TODO: need this?
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
    if ( ! globalState()->fiber_cache.empty() ) {
        auto f = std::move(globalState()->fiber_cache.back());
        globalState()->fiber_cache.pop_back();
        HILTI_RT_DEBUG("fibers", fmt("[%p] reusing fiber from cache", f.get()));
        return f;
    }

    return std::make_unique<Fiber>();
}

void detail::Fiber::destroy(std::unique_ptr<detail::Fiber> f) {
    if ( f->_state == State::Yielded )
        f->abort();

    if ( globalState()->fiber_cache.size() < CacheSize ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] putting fiber back into cache", f.get()));
        globalState()->fiber_cache.push_back(std::move(f));
        return;
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] cache size exceeded, deleting finished fiber", f.get()));
}

void detail::Fiber::primeCache() {
    std::vector<std::unique_ptr<Fiber>> fibers;
    fibers.reserve(CacheSize);

    for ( unsigned int i = 0; i < CacheSize; i++ )
        fibers.emplace_back(Fiber::create());

    while ( fibers.size() ) {
        // Fiber::destroy(std::move(fibers.back())); TODO
        fibers.pop_back();
    }
}

void detail::Fiber::reset() {
    globalState()->fiber_cache.clear();
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
                   fmt("[%p/%s/asan] start_switch_fiber %p/%p (fake_stack=%p)", context::detail::get()->current_fiber,
                       tag, stack_bottom, stack_size, &_asan.fake_stack));
    __sanitizer_start_switch_fiber(&_asan.fake_stack, stack_bottom, stack_size);
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] start_switch_fiber in %s", context::detail::get()->current_fiber, tag));
#endif
}

void detail::Fiber::_finishSwitchFiber(const char* tag) {
#ifdef HILTI_HAVE_SANITIZER
    __sanitizer_finish_switch_fiber(_asan.fake_stack, &_asan.prev_bottom, &_asan.prev_size);
    HILTI_RT_DEBUG("fibers",
                   fmt("[%p/%s/asan] finish_switch_fiber %p/%p (fake_stack=%p)", context::detail::get()->current_fiber,
                       tag, _asan.prev_bottom, _asan.prev_size, _asan.fake_stack));
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] finish_switch_fiber in %s", context::detail::get()->current_fiber, tag));
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
        .cached = globalState()->fiber_cache.size(),
        .max = _max_fibers,
        .initialized = _initialized,
    };

    return stats;
}
