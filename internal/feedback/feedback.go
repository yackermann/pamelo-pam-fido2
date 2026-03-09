package feedback

import (
	"sync"
)

const (
	LevelMinimal     = "minimal"
	LevelInteractive = "interactive"
)

type Sink interface {
	Info(msg string)
	Error(msg string)
	Debug(msg string)
}

type Reporter interface {
	Info(msg string)
	Error(msg string)
	Debug(msg string)
}

type adapter struct {
	level string
	sink  Sink
}

func New(level string, sink Sink) Reporter {
	if level == "" {
		level = LevelInteractive
	}
	return &adapter{level: level, sink: sink}
}

func (a *adapter) Info(msg string) {
	if a.level == LevelInteractive {
		a.sink.Info(msg)
	}
}

func (a *adapter) Error(msg string) {
	a.sink.Error(msg)
}

func (a *adapter) Debug(msg string) {
	a.sink.Debug(msg)
}

type BufferSink struct {
	mu     sync.Mutex
	Infos  []string
	Errors []string
	Debugs []string
}

func (b *BufferSink) Info(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Infos = append(b.Infos, msg)
}

func (b *BufferSink) Error(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Errors = append(b.Errors, msg)
}

func (b *BufferSink) Debug(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Debugs = append(b.Debugs, msg)
}
