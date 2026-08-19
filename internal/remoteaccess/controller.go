package remoteaccess

import (
	"context"
	"fmt"
)

// LaunchPlan is the controller-owned, secret-free input to a host-local
// transport. It is suitable for a short-lived local artifact, but not a
// credential: Transport implementations must invoke Authorize at connection
// time and must not expose any guest path other than WorkspaceTarget.
type LaunchPlan struct {
	Schema           string           `json:"schema"`
	Descriptor       LaunchDescriptor `json:"descriptor"`
	WorkingDirectory string           `json:"working_directory"`
}

// Transport connects a real host-local browser terminal or IDE transport. The
// adapter remains outside the authorization model: it receives no workload
// token, and it must invoke authorize immediately before admitting a client.
type Transport interface {
	Launch(ctx context.Context, plan LaunchPlan, authorize func() error) error
}

// Controller joins descriptor issuance to the actual host-local launch seam.
// A nil Transport intentionally fails closed; BoxedAi does not claim that a
// browser terminal or SSH service exists merely because a grant permits one.
type Controller struct {
	broker    *Broker
	transport Transport
	admit     func() error
}

func NewController(broker *Broker, transport Transport) *Controller {
	return &Controller{broker: broker, transport: transport}
}

// SetAdmissionGate binds a controller-local runtime check to every transport
// admission. The CLI uses it to recheck that the owning session remains live;
// the broker continues to enforce the sealed grant and workspace binding.
func (c *Controller) SetAdmissionGate(admit func() error) {
	if c != nil {
		c.admit = admit
	}
}

// Prepare issues and authorizes one short-lived, session-scoped launch plan.
func (c *Controller) Prepare(request LaunchRequest) (LaunchPlan, error) {
	if c == nil || c.broker == nil {
		return LaunchPlan{}, fmt.Errorf("%w: controller is unavailable", ErrTransportUnsupported)
	}
	descriptor, err := c.broker.Issue(request)
	if err != nil {
		return LaunchPlan{}, err
	}
	if err := c.broker.Authorize(descriptor); err != nil {
		return LaunchPlan{}, err
	}
	return LaunchPlan{
		Schema:           "boxedai.remote-access/v1",
		Descriptor:       descriptor,
		WorkingDirectory: WorkspaceTarget,
	}, nil
}

// AuthorizeRequest rechecks a controller-local request at relay admission.
func (c *Controller) AuthorizeRequest(request LaunchRequest) error {
	if c == nil || c.broker == nil {
		return ErrTransportUnsupported
	}
	c.broker.mu.RLock()
	defer c.broker.mu.RUnlock()
	return c.broker.authorizeRequestLocked(request)
}

// Launch validates a plan again immediately before delegating to the concrete
// transport. The callback lets a long-lived transport recheck revocation and
// expiry at its own client-admission boundary.
func (c *Controller) Launch(ctx context.Context, plan LaunchPlan) error {
	if c == nil || c.broker == nil || c.transport == nil {
		return ErrTransportUnsupported
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	authorize := func() error {
		if c.admit != nil {
			if err := c.admit(); err != nil {
				return err
			}
		}
		return c.broker.Authorize(plan.Descriptor)
	}
	if err := authorize(); err != nil {
		return err
	}
	return c.transport.Launch(ctx, plan, authorize)
}

func validatePlan(plan LaunchPlan) error {
	if plan.Schema != "boxedai.remote-access/v1" || plan.WorkingDirectory != WorkspaceTarget || plan.Descriptor.Target != targetFor(plan.Descriptor.Surface) {
		return ErrWorkspaceTarget
	}
	return nil
}
