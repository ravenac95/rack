package manifest

import "fmt"

const ServiceMapSizeIncrement = 5

// Group - A service group
type Group struct {
	Name           string
	Services       []*Service
	ServiceMap     map[string]*Service
	serviceMapSize uint16
}

func NewGroup(name string) Group {
	serviceMap := make(map[string]*Service, ServiceMapSizeIncrement)
	var services []*Service
	return Group{
		Name:       name,
		ServiceMap: serviceMap,
		Services:   services,
	}
}

// AddService - Adds a service to a group
func (g *Group) AddService(service Service) {
	g.Services = append(g.Services, &service)

	// Add the service to the service map.
	// If it's too big then grow the map
	if len(g.Services)%ServiceMapSizeIncrement == 0 {
		newServiceMap := make(map[string]*Service, g.serviceMapSize+ServiceMapSizeIncrement)
		for serviceName, service := range g.ServiceMap {
			newServiceMap[serviceName] = service
		}
		g.ServiceMap = newServiceMap
	}
	g.ServiceMap[service.Name] = &service
}

func (g Group) ParamName(name string) string {
	return fmt.Sprintf("%s%sGroup", UpperName(g.Name), name)
}

func (g Group) ServicesWithLoadBalancers() []*Service {
	var services []*Service
	for _, service := range g.Services {
		if service.HasBalancer() {
			services = append(services, service)
		}
	}
	return services
}

// Links - Lists the links for a group
func (g Group) Links(serviceName string) []string {
	matchingService, matchingServiceExists := g.ServiceMap[serviceName]
	if !matchingServiceExists {
		return []string{}
	}
	links := matchingService.Links
	var filteredLinks []string
	for _, link := range links {
		if _, ok := g.ServiceMap[link]; ok {
			filteredLinks = append(filteredLinks, link)
		}
	}
	return filteredLinks
}

func (g Group) HasBalancer() bool {
	for _, service := range g.Services {
		if service.HasBalancer() {
			return true
		}
	}
	return false
}

func (g Group) DeploymentMinimum() string {
	return "100"
}

func (g Group) DeploymentMaximum() string {
	return "200"
}

func AddOrUpdateGroup(groupName string, service Service, groupMap map[string]*Group, groups []*Group) []*Group {
	if group, ok := groupMap[groupName]; ok {
		group.AddService(service)
	} else {
		group := NewGroup(groupName)
		group.AddService(service)
		groups = append(groups, &group)
		groupMap[groupName] = &group
	}
	return groups
}
