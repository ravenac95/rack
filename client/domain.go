package client

import (
	"fmt"
	"time"
)

type Domain struct {
	Certificate string    `json:"certificate"`
	Domain      string    `json:"domain"`
	Expiration  time.Time `json:"expiration"`
	Port        int       `json:"port"`
	Process     string    `json:"process"`
	Secure      bool      `json:"secure"`
}

type Domains []Domain

func (c *Client) ListDomains(app string) (*Domains, error) {
	var domains Domains

	err := c.Get(fmt.Sprintf("/apps/%s/domain", app), &domains)

	if err != nil {
		return nil, err
	}

	return &domains, nil
}

func (c *Client) UpdateDomain(app, process, port, id string) (*Domain, error) {
	params := Params{
		"id": id,
	}

	var domain Domain

	err := c.Put(fmt.Sprintf("/apps/%s/domain/%s/%s", app, process, port), params, &domain)

	if err != nil {
		return nil, err
	}

	return &domain, nil
}
