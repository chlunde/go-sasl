package sasl

import "context"

// ClientMechFactory is used to create a server mechanism.
type ClientMechFactory func(state interface{}) ClientMech

// Client aids in the encapsulation of all the supported mechanisms.
type Client struct {
	factories map[string]ClientMechFactory
}

// RegisterMechFactory registers the mechanism factory by name.
func (c *Client) RegisterMechFactory(mechName string, factory ClientMechFactory) {
	if c.factories == nil {
		c.factories = make(map[string]ClientMechFactory)
	}

	c.factories[mechName] = factory
}

// Auth authenticates/authorizes a user with the named mechanism.
func (c *Client) Auth(ctx context.Context, state interface{}, mechName string, incoming <-chan []byte, outgoing chan<- []byte) error {
	factory, ok := c.factories[mechName]
	if !ok {
		return newError("sasl mechanism '%' has not been registered", nil)
	}

	mech := factory(state)

	return ConverseAsClient(ctx, mech, incoming, outgoing)
}
