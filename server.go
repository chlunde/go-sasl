package sasl

import "context"

// ServerMechFactory is used to create a server mechanism.
type ServerMechFactory func(state interface{}) ServerMech

// Server aids in the encapsulation of all the supported mechanisms.
type Server struct {
	factories map[string]ServerMechFactory
}

// RegisterMechFactory registers the mechanism factory by name.
func (s *Server) RegisterMechFactory(mechName string, factory ServerMechFactory) {
	if s.factories == nil {
		s.factories = make(map[string]ServerMechFactory)
	}

	s.factories[mechName] = factory
}

// Auth authenticates/authorizes a user with the named mechanism.
func (s *Server) Auth(ctx context.Context, state interface{}, mechName string, response []byte, incoming <-chan []byte, outgoing chan<- []byte) error {
	factory, ok := s.factories[mechName]
	if !ok {
		return newError("sasl mechanism '%' has not been registered", nil)
	}

	mech := factory(state)
	if closer, ok := mech.(MechCloser); ok {
		defer closer.Close()
	}

	return ConverseAsServer(ctx, mech, response, incoming, outgoing)
}
