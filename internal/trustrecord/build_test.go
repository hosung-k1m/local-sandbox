package trustrecord

import (
	"strings"
	"testing"

	"boxedai/internal/evidence"
)

func TestBuildActivityBindsObservedModelsToolsAndEffects(t *testing.T) {
	records := []observedRecord{
		{
			sequence: 1,
			name:     evidence.EventModelRequested,
			attrs: map[string]any{
				evidence.AttrActionID:      "model-action",
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				attrModelProvider:          "openai",
				attrModelID:                "gpt-test",
			},
		},
		{
			sequence: 2,
			name:     evidence.EventModelCompleted,
			attrs: map[string]any{
				evidence.AttrActionID:      "model-action",
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				attrModelProvider:          "openai",
				attrUsageInput:             int64(11),
				attrUsageOutput:            int64(7),
				attrUsageTotal:             int64(18),
			},
		},
		{
			sequence: 3,
			name:     evidence.EventAuthorizationDecided,
			attrs: map[string]any{
				evidence.AttrActionID:      "tool-action",
				evidence.AttrOutcome:       string(evidence.OutcomeSuccess),
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				attrToolName:               "github",
				attrToolOperation:          "repo_view",
			},
		},
		{
			sequence: 4,
			name:     evidence.EventInternalToolDispatched,
			attrs: map[string]any{
				evidence.AttrActionID:      "tool-action",
				evidence.AttrOutcome:       string(evidence.OutcomeSuccess),
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				attrToolName:               "github",
				attrToolOperation:          "repo_view",
			},
		},
		{
			sequence: 5,
			name:     evidence.EventEffectDispatched,
			attrs: map[string]any{
				evidence.AttrActionID:      "effect-action",
				evidence.AttrOutcome:       string(evidence.OutcomeSuccess),
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				evidence.AttrContentDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				attrEffectAdapter:          "github",
				attrEffectOperation:        "push",
			},
		},
		{
			sequence: 6,
			name:     evidence.EventInternalToolDispatched,
			attrs: map[string]any{
				evidence.AttrActionID:      "spoofed-tool-action",
				evidence.AttrProducer:      string(evidence.ChannelWorkload),
				evidence.AttrEvidenceClass: string(evidence.ClassModelSelfReported),
				attrToolName:               "spoofed",
				attrToolOperation:          "run",
			},
		},
	}

	activity, err := buildActivity(records)
	if err != nil {
		t.Fatalf("buildActivity: %v", err)
	}
	if activity.ModelRequestCount != 1 || len(activity.Models) != 1 {
		t.Fatalf("model activity = %+v, want one request", activity)
	}
	model := activity.Models[0]
	if model.Provider != "openai" || model.ModelID != "gpt-test" || model.RequestCount != 1 {
		t.Errorf("model = %+v, want openai/gpt-test request", model)
	}
	if model.Usage == nil || model.Usage.InputTokens == nil || *model.Usage.InputTokens != 11 || model.Usage.OutputTokens == nil || *model.Usage.OutputTokens != 7 || model.Usage.TotalTokens == nil || *model.Usage.TotalTokens != 18 {
		t.Errorf("usage = %+v, want observed 11/7/18", model.Usage)
	}
	if len(activity.Tools) != 1 || activity.Tools[0].Name != "github" || activity.Tools[0].CallCount != 1 {
		t.Errorf("tools = %+v, want one github dispatch", activity.Tools)
	}
	if activity.EffectDispatchCount != 1 || activity.ToolTranscript.CallCount != 2 || activity.ToolTranscript.EventCount != 3 {
		t.Errorf("dispatch/transcript counts = effect:%d transcript:%+v", activity.EffectDispatchCount, activity.ToolTranscript)
	}
	if activity.ToolTranscript.Digest == "" {
		t.Error("tool transcript digest is empty")
	}
}

func TestBuildActivityRejectsFractionalTokenUsage(t *testing.T) {
	records := []observedRecord{
		{
			sequence: 1,
			name:     evidence.EventModelCompleted,
			attrs: map[string]any{
				evidence.AttrProducer:      string(evidence.ChannelBroker),
				evidence.AttrEvidenceClass: string(evidence.ClassBrokerMediated),
				attrModelProvider:          "openai",
				attrUsageInput:             1.5,
			},
		},
	}

	if _, err := buildActivity(records); err == nil || !strings.Contains(err.Error(), "not a safe integer") {
		t.Fatalf("buildActivity error = %v, want fractional token rejection", err)
	}
}
