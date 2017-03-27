package manifest_test

import (
	"fmt"
	"testing"

	"github.com/convox/rack/manifest"
	"github.com/stretchr/testify/assert"
)

func TestTag(t *testing.T) {
	s := manifest.Service{
		Name: "foo",
	}
	assert.Equal(t, s.Tag("api"), "api/foo")

	s = manifest.Service{
		Name: "foo_bar",
	}
	assert.Equal(t, s.Tag("api"), "api/foo-bar")
}

func TestLabelsByPrefix(t *testing.T) {

	labels := manifest.Labels{
		"foofake": "label",
		"foo_foo": "under_bar",
		"foo-bar": "hypen-string",
		"te-st":   "hypen-string",
		"bahtest": "hypen-string",
	}

	s := manifest.Service{
		Labels: labels,
	}

	prefixed := s.LabelsByPrefix("foo")
	assert.Equal(t, map[string]string{
		"foofake": "label",
		"foo_foo": "under_bar",
		"foo-bar": "hypen-string",
	}, prefixed)
}

func TestNetworkName(t *testing.T) {
	networks := manifest.Networks{
		"foo": manifest.InternalNetwork{
			"external": manifest.ExternalNetwork{
				Name: "foonet",
			},
		},
	}

	s := manifest.Service{
		Networks: networks,
	}

	assert.Equal(t, s.NetworkName(), "foonet")
}

func TestDefaultNetworkName(t *testing.T) {
	networks := manifest.Networks{}

	s := manifest.Service{
		Networks: networks,
	}

	assert.Equal(t, s.NetworkName(), "")
}

func TestSyncPaths(t *testing.T) {
	m, err := manifestFixture("sync-path")
	if err != nil {
		assert.FailNow(t, fmt.Sprintf("failed to read fixture: %s", err.Error()))
	}

	expectedMap := map[string]string{
		".":            "/app",
		"Gemfile":      "/app/Gemfile",
		"Gemfile.lock": "/app/Gemfile.lock",
		"Rakefile":     "/app/Rakefile",
		"config":       "/app/config/bar",
		"public":       "/app/public/$FAKE",
		"app/assets":   "/app/app/assets",
	}

	for _, s := range m.Services {
		sp, err := s.SyncPaths()

		if assert.NoError(t, err) {
			assert.EqualValues(t, expectedMap, sp)
		}
	}
}

func TestGroupName(t *testing.T) {
	m, err := manifestFixture("group")
	if err != nil {
		assert.FailNow(t, fmt.Sprintf("failed to read fixture: %s", err.Error()))
	}
	webService := m.Services["web"]
	reverseProxyService := m.Services["reverse-proxy"]
	workerService := m.Services["worker"]
	assert.Equal(t, "web", webService.GroupName())
	assert.Equal(t, "web", reverseProxyService.GroupName())
	assert.Equal(t, "worker", workerService.GroupName())
}

func TestUseSecureEnvironment(t *testing.T) {
	m, err := manifestFixture("secure-env")
	if err != nil {
		assert.FailNow(t, fmt.Sprintf("failed to read fixture: %s", err.Error()))
	}
	secureService := m.Services["secure"]
	notSecureService := m.Services["notsecure"]

	assert.True(t, secureService.UseSecureEnvironment())
	assert.False(t, notSecureService.UseSecureEnvironment())
}
