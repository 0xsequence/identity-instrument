package tracing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

type Log struct {
	Time       time.Time      `json:"time"`
	Level      slog.Level     `json:"level"`
	Message    string         `json:"msg"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

func (l *Log) UnmarshalJSON(data []byte) error {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	l.Attributes = make(map[string]any)

	for k, v := range rawMap {
		switch k {
		case "time":
			if err := json.Unmarshal(v, &l.Time); err != nil {
				return fmt.Errorf("unmarshal %q: %w", k, err)
			}
		case "msg":
			if err := json.Unmarshal(v, &l.Message); err != nil {
				return fmt.Errorf("unmarshal %q: %w", k, err)
			}
		case "level":
			if err := json.Unmarshal(v, &l.Level); err != nil {
				return fmt.Errorf("unmarshal %q: %w", k, err)
			}
		default:
			var value any
			if err := json.Unmarshal(v, &value); err != nil {
				return fmt.Errorf("unmarshal %q: %w", k, err)
			}
			l.Attributes[k] = value
		}
	}

	return nil
}

func ExtractLogs(ctx context.Context, logger *slog.Logger, span *Span) error {
	logs, err := span.getLogs()
	if err != nil {
		return err
	}

	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Time.Before(logs[j].Time)
	})

	for _, log := range logs {
		attrs := make([]slog.Attr, 0, len(log.Attributes))
		for k, v := range log.Attributes {
			attrs = append(attrs, slog.Any(k, v))
		}

		record := slog.Record{
			Level:   log.Level,
			Message: log.Message,
			Time:    log.Time,
		}
		record.AddAttrs(attrs...)
		logger.Handler().Handle(ctx, record)
	}

	return nil
}

func (s *Span) getLogs() ([]*Log, error) {
	logs := make([]*Log, len(s.Logs))
	for i, log := range s.Logs {
		if err := json.Unmarshal(log, &logs[i]); err != nil {
			return nil, err
		}
	}

	for _, child := range s.Children {
		childLogs, err := child.getLogs()
		if err != nil {
			return nil, err
		}
		logs = append(logs, childLogs...)
	}

	if s.Metadata != nil {
		if msg, ok := s.Metadata["exception.message"].(string); ok {
			attrs := make(map[string]any)
			for k, v := range s.Annotations {
				attrs[k] = v
			}
			logs = append(logs, &Log{
				Time:       s.EndTime,
				Level:      slog.LevelError,
				Message:    msg,
				Attributes: attrs,
			})
		}
	}

	return logs, nil
}
