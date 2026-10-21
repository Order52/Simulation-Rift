// The browser host's Qt WebEngine window (docs/architecture.md §9.2).
// Declared to Rust in src/bridge.rs.
#pragma once

#include <cstdint>

#include "rust/cxx.h"

std::int32_t run_browser(std::uint16_t proxy_port);
void post_load(rust::Str url);
void post_close();
rust::String engine_version();
