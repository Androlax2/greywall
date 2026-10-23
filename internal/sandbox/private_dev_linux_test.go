//go:build linux

package sandbox

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func TestWrapCommandLinux_PrivateDevicesWorkAtRuntime(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")
	seedGreyproxyDir(t)
	command, err := WrapCommandLinuxWithOptions(&config.Config{},
		`test -c /dev/null && test -c /dev/zero && test -c /dev/urandom && test -d /dev/pts && test -d /dev/shm && test ! -e /dev/snd && test ! -e /dev/video0 && printf PRIVATE_DEV_OK`,
		nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // runs the generated sandbox command
	if err != nil {
		t.Fatalf("sandbox failed: %v\n%s", err, output)
	}
	if string(output) != "PRIVATE_DEV_OK" {
		t.Errorf("unexpected sandbox output: %s", output)
	}
}

func TestWrapCommandLinux_DoesNotExposeHostDevices(t *testing.T) {
	for _, mode := range []struct {
		name string
		opts LinuxSandboxOptions
	}{
		{"enforcing", LinuxSandboxOptions{}},
		{"audio", LinuxSandboxOptions{AllowAudio: true}},
		{"watch", LinuxSandboxOptions{Watch: true}},
		{"learning", LinuxSandboxOptions{Learning: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			seedGreyproxyDir(t)
			command, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", mode.opts)
			if err != nil {
				t.Fatal(err)
			}
			outerCommand, _, _ := strings.Cut(command, " -- ")
			if !strings.Contains(outerCommand, " --dev /dev ") {
				t.Error("sandbox has no private device filesystem")
			}
			for _, mount := range parseBwrapMounts(command) {
				if mount.src == "/dev" || strings.HasPrefix(mount.src, "/dev/") && mount.src != "/dev/null" && mount.src != "/dev/net/tun" {
					t.Errorf("host device tree exposed: %+v", mount)
				}
			}
		})
	}
}
