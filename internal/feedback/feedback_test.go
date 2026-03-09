package feedback

import "testing"

func TestInteractiveLevelShowsInfo(t *testing.T) {
	sink := &BufferSink{}
	r := New(LevelInteractive, sink)

	r.Info("hello")
	r.Error("err")
	r.Debug("dbg")

	if len(sink.Infos) != 1 {
		t.Fatalf("expected 1 info message, got %d", len(sink.Infos))
	}
	if len(sink.Errors) != 1 {
		t.Fatalf("expected 1 error message")
	}
	if len(sink.Debugs) != 1 {
		t.Fatalf("expected 1 debug message")
	}
}

func TestMinimalLevelSuppressesInfo(t *testing.T) {
	sink := &BufferSink{}
	r := New(LevelMinimal, sink)

	r.Info("hello")
	r.Error("err")

	if len(sink.Infos) != 0 {
		t.Fatalf("expected info suppressed in minimal mode")
	}
	if len(sink.Errors) != 1 {
		t.Fatalf("expected errors to be shown")
	}
}
