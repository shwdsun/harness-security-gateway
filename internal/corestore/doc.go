// Package corestore owns agentd's durable business state.
//
// It exposes domain operations instead of a generic repository API. Connector
// payloads are reduced to bounded scalar fields before reaching this package;
// raw platform payloads and open-ended JSON objects are never persisted.
package corestore
