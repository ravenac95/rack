package models

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/iam"
)

type Domain struct {
	Certificate string    `json:"certificate"`
	Expiration  time.Time `json:"expiration"`
	Domain      string    `json:"domain"`
	Process     string    `json:"process"`
	Port        int       `json:"port"`
	Secure      bool      `json:"secure"`
}

type Domains []Domain

func ListDomains(a string) (Domains, error) {
	app, err := GetApp(a)

	if err != nil {
		return nil, err
	}

	domains := make(Domains, 0)
	fmt.Println(domains)

	return domains, nil
}

func UpdateDomain(app, process string, port int, id string) (*Domain, error) {
	a, err := GetApp(app)

	if err != nil {
		return nil, err
	}

	// validate app is not currently updating
	if a.Status != "running" {
		return nil, fmt.Errorf("can not update app with status: %s", a.Status)
	}

	outputs := a.Outputs
	balancer := outputs[fmt.Sprintf("%sPort%dBalancerName", UpperName(process), port)]

	if balancer == "" {
		return nil, fmt.Errorf("Process and port combination unknown")
	}

	arn := ""

	if strings.HasPrefix(id, "acm-") {
		uuid := id[4:]

		res, err := ACM().ListCertificates(nil)

		if err != nil {
			return nil, err
		}

		for _, cert := range res.CertificateSummaryList {
			parts := strings.Split(*cert.CertificateArn, "-")

			if parts[len(parts)-1] == uuid {
				res, err := ACM().DescribeCertificate(&acm.DescribeCertificateInput{
					CertificateArn: cert.CertificateArn,
				})

				if err != nil {
					return nil, err
				}

				if *res.Certificate.Status == "PENDING_VALIDATION" {
					return nil, fmt.Errorf("%s is still pending validation", id)
				}

				arn = *cert.CertificateArn
				break
			}
		}
	} else {
		res, err := IAM().GetServerCertificate(&iam.GetServerCertificateInput{
			ServerCertificateName: aws.String(id),
		})

		if err != nil {
			return nil, err
		}

		arn = *res.ServerCertificate.ServerCertificateMetadata.Arn
	}

	// update cloudformation
	req := &cloudformation.UpdateStackInput{
		StackName:           aws.String(a.StackName()),
		Capabilities:        []*string{aws.String("CAPABILITY_IAM")},
		UsePreviousTemplate: aws.Bool(true),
	}

	params := a.Parameters
	params[fmt.Sprintf("%sPort%dCertificate", UpperName(process), port)] = arn

	for key, val := range params {
		req.Parameters = append(req.Parameters, &cloudformation.Parameter{
			ParameterKey:   aws.String(key),
			ParameterValue: aws.String(val),
		})
	}

	// TODO: The existing cert will be orphaned. Deleting it now could cause
	// CF problems if the stack tries to rollback and use the old cert.
	_, err = UpdateStack(req)

	if err != nil {
		return nil, err
	}

	domain := Domain{
		Port:    port,
		Process: process,
	}

	return &domain, nil
}

// fetch certificate from CF params and parse name from arn
func domainName(app, process string, port int) string {
	key := fmt.Sprintf("%sPort%dCertificate", UpperName(process), port)

	a, err := GetApp(app)

	if err != nil {
		fmt.Printf(err.Error())
		return ""
	}

	arn := a.Parameters[key]

	slice := strings.Split(arn, "/")

	return slice[len(slice)-1]
}
