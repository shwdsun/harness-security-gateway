// Package logaudit contains no runtime code. It holds the recurring audit that
// pins what the deployed services may write to their logs, so a new log line
// cannot silently begin disclosing message text, credentials or provider
// output into the operator's journal.
package logaudit
