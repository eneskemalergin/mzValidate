//! Allocation-free validation progress observation.

/// Validation work that can expose meaningful byte progress.
pub const Phase = enum {
    parse,
    checksum,
};

/// One monotonic byte-progress update for a validation phase.
pub const Update = struct {
    phase: Phase,
    completed_bytes: u64,
    total_bytes: u64,
};

/// Caller-owned observer invoked synchronously during validation.
pub const Observer = struct {
    context: *anyopaque,
    update_fn: *const fn (context: *anyopaque, update: Update) void,

    pub fn report(observer: Observer, update: Update) void {
        observer.update_fn(observer.context, update);
    }
};

/// Byte distance between observer calls from validation hot paths.
pub const checkpoint_bytes: u64 = 4 * 1024 * 1024;

/// Emits bounded, monotonic updates without allocating or reading a clock.
pub const Reporter = struct {
    observer: Observer,
    phase: Phase,
    total_bytes: u64,
    next_checkpoint: u64 = checkpoint_bytes,
    last_reported: u64 = 0,
    has_reported: bool = false,

    pub fn init(observer: Observer, phase: Phase, total_bytes: u64) Reporter {
        return .{
            .observer = observer,
            .phase = phase,
            .total_bytes = total_bytes,
        };
    }

    pub fn checkpoint(reporter: *Reporter, completed_bytes: u64) void {
        const completed = @min(completed_bytes, reporter.total_bytes);
        if (completed < reporter.next_checkpoint and completed < reporter.total_bytes) return;
        if (reporter.has_reported and completed <= reporter.last_reported) return;

        reporter.observer.report(.{
            .phase = reporter.phase,
            .completed_bytes = completed,
            .total_bytes = reporter.total_bytes,
        });
        reporter.has_reported = true;
        reporter.last_reported = completed;
        reporter.next_checkpoint = completed +| checkpoint_bytes;
    }

    pub fn complete(reporter: *Reporter) void {
        reporter.checkpoint(reporter.total_bytes);
    }
};

test "[unit]: reporter bounds callbacks and completes monotonically" {
    const Recorder = struct {
        updates: [4]Update = undefined,
        len: usize = 0,

        fn observe(context: *anyopaque, update: Update) void {
            const recorder: *@This() = @ptrCast(@alignCast(context));
            recorder.updates[recorder.len] = update;
            recorder.len += 1;
        }
    };

    var recorder = Recorder{};
    var reporter = Reporter.init(.{
        .context = &recorder,
        .update_fn = Recorder.observe,
    }, .parse, checkpoint_bytes * 2 + 1);

    reporter.checkpoint(checkpoint_bytes - 1);
    reporter.checkpoint(checkpoint_bytes);
    reporter.checkpoint(checkpoint_bytes + 1);
    reporter.complete();
    reporter.complete();

    try @import("std").testing.expectEqual(@as(usize, 2), recorder.len);
    try @import("std").testing.expectEqual(checkpoint_bytes, recorder.updates[0].completed_bytes);
    try @import("std").testing.expectEqual(checkpoint_bytes * 2 + 1, recorder.updates[1].completed_bytes);
}
