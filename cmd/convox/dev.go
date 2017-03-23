// build devtools

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"io/ioutil"

	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/convox/rack/client"
	"github.com/convox/rack/cmd/convox/stdcli"
	"gopkg.in/urfave/cli.v1"
)

const DevRackSettingsKey = "dev-rack-settings.json"

type DevRackSettings struct {
	ConvoxAPIRepositoryURI   string `json:"convox_api_repository_uri"`
	ConvoxBuildRepositoryURI string `json:"convox_build_repository_uri"`
	ConvoxFormationURL       string `json:"convox_formation_url"`
}

var envKeyReplaceRegex = regexp.MustCompile("(.)([A-Z])")

type DevRackChange struct {
	ChangeType string
	Options    map[string]string
}

type DevRack struct {
	StackName    string
	Region       string
	Env          map[string]string
	RackSettings *DevRackSettings
	stack        *cloudformation.Stack
	client       *client.Client
	awsSess      *session.Session
	changeQueue  []DevRackChange
}

func NewDevRack(client *client.Client) (*DevRack, error) {
	system, err := client.GetSystem()
	if err != nil {
		return nil, err
	}
	stackName := system.Name
	region := system.Region

	session, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, err
	}

	devRack := DevRack{
		StackName: stackName,
		Region:    region,
		awsSess:   session,
		client:    client,
	}

	err = devRack.LoadEnv()
	if err != nil {
		return nil, err
	}
	err = devRack.LoadDevRackSettings()
	if err != nil {
		return nil, err
	}

	return &devRack, nil
}

func (d *DevRack) ec2() *ec2.EC2 {
	return ec2.New(d.awsSess)
}

func (d *DevRack) ecr() *ecr.ECR {
	return ecr.New(d.awsSess)
}

func (d *DevRack) s3() *s3.S3 {
	return s3.New(d.awsSess)
}

func (d *DevRack) cf() *cloudformation.CloudFormation {
	return cloudformation.New(d.awsSess)
}

// EnableDevelopmentOnRack - Enables Development=Yes on the rack params
func (d *DevRack) EnableDevelopmentOnRack() error {
	system, err := d.client.GetSystem()
	if err != nil {
		return err
	}
	params := map[string]string{
		"Development": "Yes",
	}

	fmt.Println("Ensuring Development=Yes is set for the current rack")

	err = d.client.SetParameters(system.Name, params)
	if err != nil {
		if strings.Contains(err.Error(), "No updates are to be performed") {
			return nil
		}
		return stdcli.Error(err)
	}
	return nil
}

// LoadEnv - Loads the environment
func (d *DevRack) LoadEnv() error {
	fmt.Println("Loading environment values from the Rack's output")
	params := &cloudformation.DescribeStacksInput{
		StackName: aws.String(d.StackName),
	}
	resp, err := d.cf().DescribeStacks(params)
	if err != nil {
		return err
	}
	outputs := resp.Stacks[0].Outputs
	env := make(map[string]string, len(outputs))
	for _, output := range outputs {
		env[aws.StringValue(output.OutputKey)] = aws.StringValue(output.OutputValue)
	}
	d.Env = env
	d.stack = resp.Stacks[0]
	return nil
}

// ExportEnv - Exports the stack output to an environment file that can be used with convox start
func (d *DevRack) ExportEnv(output io.WriteCloser) error {
	for key, value := range d.Env {
		envKey := strings.ToUpper(envKeyReplaceRegex.ReplaceAllString(key, "${1}_${2}"))
		_, err := fmt.Fprintf(output, "%s=%s\n", envKey, value)
		if err != nil {
			return err
		}
	}
	return output.Close()
}

func (d *DevRack) initializeDevRackSettings() error {
	if d.HasDevRackSettings() {
		return nil
	}
	rackSettings := DevRackSettings{}
	// Create Repository for convox/api
	apiRepoName := fmt.Sprintf("%s-convox-api", d.StackName)

	apiRepoURI, err := d.EnsureEcrRepo(apiRepoName)
	if err != nil {
		return err
	}

	// Create Repository for convox/build
	buildRepoName := fmt.Sprintf("%s-convox-build", d.StackName)

	buildRepoURI, err := d.EnsureEcrRepo(buildRepoName)
	if err != nil {
		return err
	}
	rackSettings.ConvoxAPIRepositoryURI = apiRepoURI
	rackSettings.ConvoxBuildRepositoryURI = buildRepoURI

	d.saveDevRackSettings(&rackSettings)
	d.RackSettings = &rackSettings
	return nil
}

func (d *DevRack) saveDevRackSettings(rackSettings *DevRackSettings) error {
	settingsBucketName := d.SettingsBucket()

	body, err := json.Marshal(rackSettings)

	if err != nil {
		return err
	}

	params := s3.PutObjectInput{
		Bucket:      aws.String(settingsBucketName),
		Key:         aws.String(DevRackSettingsKey),
		ContentType: aws.String("application/json"),
		Body:        bytes.NewReader(body),
	}

	_, err = d.s3().PutObject(&params)
	if err != nil {
		return err
	}
	return nil
}

func (d *DevRack) HasDevRackSettings() bool {
	return d.RackSettings != nil
}

// LoadDevRackSettings - Loads the Dev Rack settings from the settings bucket
func (d *DevRack) LoadDevRackSettings() error {
	settingsBucketName := d.SettingsBucket()

	params := &s3.GetObjectInput{
		Bucket: aws.String(settingsBucketName),
		Key:    aws.String(DevRackSettingsKey),
	}
	output, err := d.s3().GetObject(params)
	rackSettings := DevRackSettings{}
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchKey:
				d.RackSettings = nil
				return nil
			default:
				return err
			}
		} else {
			return err
		}
	} else {
		rawRackSettings, err := ioutil.ReadAll(output.Body)
		if err != nil {
			return err
		}

		err = json.Unmarshal(rawRackSettings, &rackSettings)

		if err != nil {
			return err
		}
	}

	d.RackSettings = &rackSettings
	return nil
}

// Initialize - Initializes a rack for use as a development rack
//
// This will
//   * Enable `Development=Yes` on the rack parameters
//   * Create 2 ECR repositories to store test images
//   * Creates a `dev-rack-settings.json` file in the S3 settings bucket of the rack.
//     This is used to hold a reference to the ECR repositories.
func (d *DevRack) Initialize() error {
	err := d.EnableDevelopmentOnRack()
	if err != nil {
		return err
	}
	return d.initializeDevRackSettings()
}

// EnsureEcrRepo - Gets or Creates a repository
func (d *DevRack) EnsureEcrRepo(name string) (string, error) {
	repoURI, err := d.getEcrRepo(name)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecr.ErrCodeRepositoryNotFoundException:
				return d.createEcrRepo(name)
			}
		}
		return "", err
	}
	return repoURI, nil
}

func (d *DevRack) createEcrRepo(name string) (string, error) {
	params := ecr.CreateRepositoryInput{
		RepositoryName: aws.String(name),
	}
	resp, err := d.ecr().CreateRepository(&params)

	if err != nil {
		return "", err
	}
	return *resp.Repository.RepositoryUri, nil
}

func (d *DevRack) getEcrRepo(name string) (string, error) {
	params := ecr.DescribeRepositoriesInput{
		RepositoryNames: aws.StringSlice([]string{name}),
	}
	resp, err := d.ecr().DescribeRepositories(&params)
	if err != nil {
		return "", err
	}
	return *resp.Repositories[0].RepositoryUri, nil
}

func (d *DevRack) UpdateBuildImage(version string) {
	change := DevRackChange{
		ChangeType: "updateBuildImage",
		Options: map[string]string{
			"version": version,
		},
	}
	d.changeQueue = append(d.changeQueue, change)
}

func (d *DevRack) UpdateAPIImage(version string) {
	change := DevRackChange{
		ChangeType: "updateAPIImage",
		Options: map[string]string{
			"version": version,
		},
	}
	d.changeQueue = append(d.changeQueue, change)
}

func (d *DevRack) CommitRackChanges() error {
	parametersMap := d.cfStackParametersMapForUpdate()

	for _, change := range d.changeQueue {
		switch change.ChangeType {
		case "updateBuildImage":
			version := change.Options["version"]
			buildImage := fmt.Sprintf("%s:%s", d.RackSettings.ConvoxBuildRepositoryURI, version)
			parametersMap["BuildImage"] = &cloudformation.Parameter{
				ParameterKey:     aws.String("BuildImage"),
				ParameterValue:   aws.String(buildImage),
				UsePreviousValue: aws.Bool(false),
			}
		case "updateAPIImage":
			version := change.Options["version"]
			parametersMap["ConvoxApiImage"] = &cloudformation.Parameter{
				ParameterKey:     aws.String("ConvoxApiImage"),
				ParameterValue:   aws.String(d.RackSettings.ConvoxAPIRepositoryURI),
				UsePreviousValue: aws.Bool(false),
			}
			parametersMap["Version"] = &cloudformation.Parameter{
				ParameterKey:     aws.String("Version"),
				ParameterValue:   aws.String(version),
				UsePreviousValue: aws.Bool(false),
			}
		}
	}

	parametersMap["LambdaBucket"] = &cloudformation.Parameter{
		ParameterKey:     aws.String("LambdaBucket"),
		ParameterValue:   aws.String(d.SettingsBucket()),
		UsePreviousValue: aws.Bool(false),
	}

	parametersMap["LambdaKeyPrefix"] = &cloudformation.Parameter{
		ParameterKey:     aws.String("LambdaKeyPrefix"),
		ParameterValue:   aws.String("dev/"),
		UsePreviousValue: aws.Bool(false),
	}

	var parameters []*cloudformation.Parameter

	for _, parameter := range parametersMap {
		parameters = append(parameters, parameter)
	}

	params := cloudformation.UpdateStackInput{
		StackName:        aws.String(d.StackName),
		Capabilities:     d.stack.Capabilities,
		NotificationARNs: d.stack.NotificationARNs,
		Parameters:       parameters,
		TemplateURL:      aws.String(d.RackSettings.ConvoxFormationURL),
	}
	_, err := d.cf().UpdateStack(&params)
	return err
}

func (d *DevRack) cfStackParametersMapForUpdate() map[string]*cloudformation.Parameter {
	parametersMap := make(map[string]*cloudformation.Parameter, len(d.stack.Parameters)+10)
	for _, parameter := range d.stack.Parameters {
		parametersMap[*parameter.ParameterKey] = &cloudformation.Parameter{
			ParameterKey:     parameter.ParameterKey,
			UsePreviousValue: aws.Bool(true),
		}
	}
	return parametersMap
}

func (d *DevRack) SettingsBucket() string {
	return d.Env["SettingsBucket"]
}

func (d *DevRack) UpdateConvoxFormationURL(version string) error {
	formationURL := fmt.Sprintf(
		"https://s3-%s.amazonaws.com/%s/dev/release/%s/formation.json",
		d.Region,
		d.SettingsBucket(),
		version,
	)
	d.RackSettings.ConvoxFormationURL = formationURL
	return d.saveDevRackSettings(d.RackSettings)
}

func (d *DevRack) currentSecurityGroupIpPermissions() ([]*ec2.IpPermission, error) {
	params := ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(d.Env["SecurityGroup"]),
		},
	}

	resp, err := d.ec2().DescribeSecurityGroups(&params)
	if err != nil {
		return nil, err
	}
	return resp.SecurityGroups[0].IpPermissions, nil
}

func (d *DevRack) AddCurrentHostToSecurityGroup() error {
	myIp, err := whatsMyIp()

	if err != nil {
		return err
	}
	myIpCidr := fmt.Sprintf("%s/32", myIp)

	ipPermissions, err := d.currentSecurityGroupIpPermissions()
	if err != nil {
		return err
	}

	for _, ipPermission := range ipPermissions {
		if *ipPermission.FromPort == 0 && *ipPermission.ToPort == 65535 && *ipPermission.IpProtocol == "tcp" {
			for _, ipRange := range ipPermission.IpRanges {
				// No need to do anything this already exists!
				if *ipRange.CidrIp == myIpCidr {
					return nil
				}
			}
		}
	}

	params := ec2.AuthorizeSecurityGroupIngressInput{
		FromPort:   aws.Int64(0),
		ToPort:     aws.Int64(65535),
		CidrIp:     aws.String(myIpCidr),
		IpProtocol: aws.String("tcp"),
		GroupId:    aws.String(d.Env["SecurityGroup"]),
	}

	_, err = d.ec2().AuthorizeSecurityGroupIngress(&params)
	return err
}

type ShellCommand struct {
	cmd    string
	args   []string
	stdout io.Writer
	stderr io.Writer
}

type ShellCommandList []ShellCommand

func (scl ShellCommandList) Execute(dir string, additionalEnvVars []string) error {
	env := os.Environ()
	if additionalEnvVars != nil {
		for _, additionalEnvVar := range additionalEnvVars {
			env = append(env, additionalEnvVar)
		}
	}
	for _, shellCommand := range scl {
		cmd := exec.Command(shellCommand.cmd, shellCommand.args...)
		cmd.Env = env
		cmd.Dir = dir
		if shellCommand.stdout != nil {
			cmd.Stdout = shellCommand.stdout
		} else {
			cmd.Stdout = os.Stdout
		}
		if shellCommand.stderr != nil {
			cmd.Stderr = shellCommand.stderr
		} else {
			cmd.Stderr = os.Stderr
		}
		err := cmd.Run()

		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	stdcli.RegisterCommand(cli.Command{
		Name:        "devtools",
		Description: "developer tools",
		Usage:       "",
		Flags:       []cli.Flag{rackFlag},
		Subcommands: []cli.Command{
			{
				Name:        "deploy-local-changes",
				Description: "Deploys local convox docker images and upload local lambda zips",
				Action:      cmdDeployLocalChanges,
				Flags:       []cli.Flag{rackFlag},
			},
			{
				Name:        "setup-env",
				Description: "Automagically sets up the current directory for a development environment",
				Action:      cmdSetupEnvironment,
				Flags:       []cli.Flag{rackFlag},
			},
		},
	})
}

func getConvoxDir() (string, error) {
	convoxPath := os.Getenv("CONVOX_PATH")
	if convoxPath != "" {
		return filepath.Abs(convoxPath)
	}
	return filepath.Abs(path.Join(os.Getenv("GOPATH"), "src/github.com/convox/rack"))
}

func cmdDeployLocalChanges(c *cli.Context) error {
	devRack, err := NewDevRack(rackClient(c))

	if err != nil {
		return err
	}

	commandTable := ShellCommandList{
		ShellCommand{cmd: "make", args: []string{"builder"}},
		ShellCommand{cmd: "make", args: []string{"devrelease"}},
	}

	now := time.Now()
	// VERSION = YYYYmmddHHMMSS
	version := now.UTC().Format("20060102150405")

	var env []string
	env = append(env, fmt.Sprintf("CONVOX_BUILDER_TAG=%s", devRack.RackSettings.ConvoxBuildRepositoryURI))
	env = append(env, fmt.Sprintf("CONVOX_BUILDER_TAG_VERSION=%s", version))
	env = append(env, fmt.Sprintf("CONVOX_API_TAG=%s", devRack.RackSettings.ConvoxAPIRepositoryURI))
	env = append(env, fmt.Sprintf("CONVOX_API_TAG_VERSION=%s", version))
	env = append(env, fmt.Sprintf("DEV_RACK_SETTINGS_BUCKET=%s", devRack.SettingsBucket()))
	env = append(env, fmt.Sprintf("DEV_RACK_REGION=%s", devRack.Region))
	env = append(env, fmt.Sprintf("VERSION=%s", version))

	convoxDir, err := getConvoxDir()

	err = commandTable.Execute(convoxDir, env)
	if err != nil {
		return err
	}

	err = devRack.UpdateConvoxFormationURL(version)
	if err != nil {
		return err
	}

	devRack.UpdateAPIImage(version)
	devRack.UpdateBuildImage(version)
	return devRack.CommitRackChanges()
}

func whatsMyIp() (string, error) {
	resp, err := http.Get("http://checkip.amazonaws.com")

	if err != nil {
		return "", err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(bodyBytes)), nil
}

func cmdSetupEnvironment(c *cli.Context) error {
	devRack, err := NewDevRack(rackClient(c))
	if err != nil {
		return err
	}

	fmt.Println("Initializing Dev Rack")
	err = devRack.Initialize()
	if err != nil {
		return err
	}

	convoxDir, err := getConvoxDir()
	if err != nil {
		return err
	}

	convoxEnvFilePath := path.Join(convoxDir, ".env")

	fmt.Printf("Exporting environment to %s\n", convoxEnvFilePath)
	convoxEnvFile, err := os.Create(convoxEnvFilePath)
	if err != nil {
		return err
	}
	defer convoxEnvFile.Close()

	err = devRack.ExportEnv(convoxEnvFile)
	if err != nil {
		return err
	}

	fmt.Println("Adding current IP address to the Rack security group")
	err = devRack.AddCurrentHostToSecurityGroup()
	if err != nil {
		return err
	}

	fmt.Println("Done!")
	fmt.Println("")
	fmt.Println("If you haven't already, you can log in to the convox")
	fmt.Println("environment locally by doing the following: ")
	fmt.Println("")
	fmt.Println("$ convox start")
	fmt.Printf("$ convox login localhost -p %s\n", devRack.Env["Password"])

	return nil
}
