// Package connectorwire defines the closed JSON contract between one trusted
// connector instance and agentd's connector-specific Unix socket.
//
// Connector identity is intentionally absent from every DTO: agentd derives it
// from the socket on which the request arrived. The HTTP endpoint supplies the
// protocol version (/v1); the DTOs therefore do not carry a client-selected
// version field.
package connectorwire
