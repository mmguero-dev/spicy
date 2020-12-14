// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fiber/fiber.h>

#include <cinttypes>
#include <memory>

#include <hilti/rt/context.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

namespace hilti::rt::context::detail {
// Not part of global state, it's per thread.
thread_local Context* __current = nullptr;
Context*& current() { return __current; }
} // namespace hilti::rt::context::detail

Context::Context(vthread::ID vid) : vid(vid), main_fiber(std::make_unique<detail::Fiber>(true)), current_fiber(main_fiber.get()) {
    shared_stack = new ::Fiber;
    if ( ! ::fiber_alloc(shared_stack, 10 * 1024 * 1024, nullptr, nullptr, FIBER_FLAG_GUARD_LO | FIBER_FLAG_GUARD_HI) )
        internalError("could not allocate fiber");

    if ( vid == vthread::Master ) {
        HILTI_RT_DEBUG("libhilti", "creating master context");
        // Globals for the master context are initialized separately as we
        // may not have the state available yet.
        return;
    }

    for ( const auto& m : globalState()->hilti_modules ) {
        if ( m.init_globals )
            (*m.init_globals)(this);
    }
}

Context::~Context() {
    if ( vid == vthread::Master ) {
        HILTI_RT_DEBUG("libhilti", "destroying master context");
    }
    else {
        HILTI_RT_DEBUG("libhilti", fmt("destroying context for vid %" PRIu64, vid));
    }
}

Context* context::detail::master() { return globalState()->master_context.get(); }
