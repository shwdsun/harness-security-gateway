package discordconnector

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// MaxTokenFileBytes bounds the credential read. A larger file is a
// provisioning mistake, not a token.
const MaxTokenFileBytes = 512

// ReadToken loads the bot token from an operator-provisioned private file.
// The value never appears in an error, log line, event or state row.
func ReadToken(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open bot token file: %w", err)
	}
	file := os.NewFile(uintptr(fd), "discord-bot-token")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect bot token file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
		return "", errors.New("discordconnector: bot token must be a single-link regular file")
	}
	if int(stat.Uid) != os.Geteuid() {
		return "", errors.New("discordconnector: bot token must be owned by the connector identity")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("discordconnector: bot token must not be readable by group or others")
	}
	if info.Size() > MaxTokenFileBytes {
		return "", errors.New("discordconnector: bot token file exceeds its byte limit")
	}
	data := make([]byte, MaxTokenFileBytes+1)
	read, err := file.Read(data)
	if err != nil && read == 0 {
		return "", errors.New("discordconnector: bot token file could not be read")
	}
	token := strings.TrimSpace(string(data[:read]))
	if err := validateToken(token); err != nil {
		return "", err
	}
	return token, nil
}
