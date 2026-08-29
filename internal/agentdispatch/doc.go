// Package agentdispatch advances agentd's durable Run state machine against
// sandboxd. It has no goroutines: the daemon owns scheduling and calls the
// small step methods explicitly.
package agentdispatch
