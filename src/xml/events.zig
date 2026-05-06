//! Phase 1 placeholder for streaming XML event types.

pub const EventKind = enum {
    start_element,
    end_element,
    text,
    attribute,
};
