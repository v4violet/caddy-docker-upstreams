package caddy_docker_upstreams

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/bep/debounce"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"go.uber.org/zap"
)

const (
	Label             = "caddy"
	LabelNetwork      = "caddy.network"
	LabelUpstreamPort = "caddy.port"
)

func init() {
	caddy.RegisterModule(DockerUpstreams{})
}

type DockerUpstreams struct {
	Label string `json:"label,omitempty"`

	filters filters.Args

	upstreams   []*reverseproxy.Upstream
	upstreamsMu *sync.RWMutex

	logger *zap.Logger
}

func (DockerUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.upstreams.docker",
		New: func() caddy.Module { return new(DockerUpstreams) },
	}
}

func (du *DockerUpstreams) provisionCandidates(ctx caddy.Context, cli *client.Client) error {
	containers, err := cli.ContainerList(ctx, container.ListOptions{Filters: du.filters})
	if err != nil {
		return fmt.Errorf("listing docker containers: %w", err)
	}

	updated := make([]*reverseproxy.Upstream, 0, len(containers))

	for _, c := range containers {
		// Build upstream.
		port, ok := c.Labels[LabelUpstreamPort]
		if !ok {
			tcp_ports := []types.Port{}
			for _, port := range c.Ports {
				if port.Type != "tcp" {
					continue
				}
				tcp_ports = append(tcp_ports, port)
			}
			if len(tcp_ports) == 0 {
				du.logger.Error("unable to get port for container",
					zap.String("container_id", c.ID),
				)
				continue
			}
			port = fmt.Sprintf("%d", tcp_ports[0].PrivatePort)
		}

		// Choose network to connect.
		if len(c.NetworkSettings.Networks) == 0 {
			du.logger.Error("unable to get ip address from container networks",
				zap.String("container_id", c.ID),
			)
			continue
		}

		network, ok := c.Labels[LabelNetwork]
		if !ok {
			// Use the first network settings of container.
			for _, settings := range c.NetworkSettings.Networks {
				address := net.JoinHostPort(settings.IPAddress, port)
				updated = append(updated, &reverseproxy.Upstream{Dial: address})
				break
			}
			continue
		}

		settings, ok := c.NetworkSettings.Networks[network]
		if !ok {
			// Add project prefix. See also https://github.com/compose-spec/compose-go/blob/main/loader/normalize.go.
			const projectLabel = "com.docker.compose.project"
			project, ok := c.Labels[projectLabel]
			if !ok {
				du.logger.Error("unable to get network settings from container",
					zap.String("container_id", c.ID),
					zap.String("network", network),
				)
				continue
			}

			network = fmt.Sprintf("%s_%s", project, network)
			settings, ok = c.NetworkSettings.Networks[network]
			if !ok {
				du.logger.Error("unable to get network settings from container",
					zap.String("container_id", c.ID),
					zap.String("network", network),
				)
				continue
			}
		}

		address := net.JoinHostPort(settings.IPAddress, port)
		updated = append(updated, &reverseproxy.Upstream{Dial: address})
	}

	du.upstreamsMu.Lock()
	du.upstreams = updated
	du.upstreamsMu.Unlock()

	return nil
}

func (du *DockerUpstreams) keepUpdated(ctx caddy.Context, cli *client.Client) {
	defer cli.Close()

	debounced := debounce.New(100 * time.Millisecond)

	for {
		messages, errs := cli.Events(ctx, events.ListOptions{
			Filters: filters.NewArgs(filters.Arg("type", string(events.ContainerEventType))),
		})

	selectLoop:
		for {
			select {
			case <-messages:
				debounced(func() {
					err := du.provisionCandidates(ctx, cli)
					if err != nil {
						du.logger.Error("unable to provision the candidates", zap.Error(err))
					}
				})
			case err := <-errs:
				if errors.Is(err, context.Canceled) {
					return
				}

				du.logger.Warn("unable to monitor container events; will retry", zap.Error(err))
				break selectLoop
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (du *DockerUpstreams) provision(ctx caddy.Context, cli *client.Client) error {
	err := du.provisionCandidates(ctx, cli)
	if err != nil {
		return err
	}

	go du.keepUpdated(ctx, cli)

	return nil
}

func (du *DockerUpstreams) Provision(ctx caddy.Context) error {
	du.Label = caddy.NewEmptyReplacer().ReplaceAll(du.Label, "")

	du.logger = ctx.Logger()
	du.upstreamsMu = new(sync.RWMutex)

	du.filters = filters.NewArgs(
		filters.Arg("label", fmt.Sprintf("%s=%s", Label, du.Label)),
		filters.Arg("status", "running"), // types.ContainerState.Status
		filters.Arg("health", types.Healthy),
		filters.Arg("health", types.NoHealthcheck),
	)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("provisioning docker client: %w", err)
	}

	ping, err := cli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("ping docker server: %w", err)
	}
	du.logger.Info("connected docker server", zap.String("api_version", ping.APIVersion), zap.String("label", du.Label))

	return du.provision(ctx, cli)
}

func (du *DockerUpstreams) GetUpstreams(r *http.Request) ([]*reverseproxy.Upstream, error) {
	upstreams := make([]*reverseproxy.Upstream, 0, len(du.upstreams))

	du.upstreamsMu.RLock()
	defer du.upstreamsMu.RUnlock()
	copy(upstreams, du.upstreams)

	return du.upstreams, nil
}

func (du *DockerUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()
	if d.NextArg() {
		du.Label = d.Val()
	} else {
		return d.Errf("unrecognized docker option '%s'", d.Val())
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*DockerUpstreams)(nil)
	_ reverseproxy.UpstreamSource = (*DockerUpstreams)(nil)
	_ caddyfile.Unmarshaler       = (*DockerUpstreams)(nil)
)
