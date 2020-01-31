/*******************************************************************************
 * Copyright 2020 Intel Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/
package commandline

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultConfigProvider = "consul.http://localhost:8500"
	DefaultConfigFile     = "configuration.toml"
)

// CommonFlags is an interface that defines AP for the common command-line flags used by most EdgeX services
type CommonFlags interface {
	UseRegistry() bool
	ConfigProviderUrl() string
	Profile() string
	ConfigDirectory() string
	ConfigFileName() string
	Parse([]string)
	Help()
}

// DefaultCommonFlags is the Default implementation of CommonFlags used by most EdgeX services
type DefaultCommonFlags struct {
	FlagSet           *flag.FlagSet
	additionalUsage   string
	useRegistry       bool
	configProviderUrl string
	profile           string
	configDir         string
	configFileName    string
}

// NewDefaultCommonFlags creates and initializes a DefaultCommonFlags
func NewDefaultCommonFlags(additionalUsage string) *DefaultCommonFlags {
	commonFlags := DefaultCommonFlags{}

	commonFlags.FlagSet = flag.NewFlagSet("", flag.ExitOnError)
	commonFlags.additionalUsage = additionalUsage
	return &commonFlags
}

// Parse parses the passed in command-lie arguments looking to the default set of common flags
func (f *DefaultCommonFlags) Parse(arguments []string) {
	// The flags package doesn't allow for String flags to be specified without a value, so to support
	// -cp/-configProvider without value to indicate using default host value we must detect use of this option with
	// out value and insert the default value before parsing the command line options.
	for index, option := range arguments {
		if strings.Contains(option, "-cp") || strings.Contains(option, "-configProvider") {
			if !strings.Contains(option, "=") {
				arguments[index] = "-cp=" + DefaultConfigProvider
			}
		}
	}

	// Usage is provided by caller, so leaving individual usage blank here so not confusing where if comes from.
	f.FlagSet.StringVar(&f.configProviderUrl, "configProvider", "", "")
	f.FlagSet.StringVar(&f.configProviderUrl, "cp", "", "")
	f.FlagSet.StringVar(&f.configFileName, "f", DefaultConfigFile, "")
	f.FlagSet.StringVar(&f.configFileName, "file", DefaultConfigFile, "")
	f.FlagSet.StringVar(&f.profile, "profile", "", "")
	f.FlagSet.StringVar(&f.profile, "p", "", ".")
	f.FlagSet.StringVar(&f.configDir, "confdir", "", "")
	f.FlagSet.BoolVar(&f.useRegistry, "registry", false, "")
	f.FlagSet.BoolVar(&f.useRegistry, "r", false, "")

	f.FlagSet.Usage = f.helpCallback

	err := f.FlagSet.Parse(arguments)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

// UseRegistry returns whether the Registry should be used or not
func (f *DefaultCommonFlags) UseRegistry() bool {
	return f.useRegistry
}

// ConfigProviderUrl returns the url for the Configuration Provider, if one was specified.
func (f *DefaultCommonFlags) ConfigProviderUrl() string {
	return f.configProviderUrl
}

// Profile returns the profile name to use, if one was specified
func (f *DefaultCommonFlags) Profile() string {
	return f.profile
}

// ConfigDirectory returns the directory where the config file(s) are located, if it was specified.
func (f *DefaultCommonFlags) ConfigDirectory() string {
	return f.configDir
}

// ConfigFileName returns the name of the local configuration file
func (f *DefaultCommonFlags) ConfigFileName() string {
	return f.configFileName
}

// Help displays the usage help message and exit.
func (f *DefaultCommonFlags) Help() {
	f.helpCallback()
}

// commonHelpCallback displays the help usage message and exits
func (f *DefaultCommonFlags) helpCallback() {
	fmt.Printf(`
Usage: %s [options]
Server Options:
    -cp, --configProvider           Indicates to use Configuration Provider service at specified URL.
                                    URL Format: {type}.{protocol}://{host}:{port} ex: consul.http://localhost:8500
    -f, --file <name>               Indicates name of the local configuration file. Defaults to configuration.toml
    -p, --profile <name>            Indicate configuration profile other than default
    --confdir                       Specify local configuration directory
    -r, --registry                  Indicates service should use Registry
%s
Common Options:
	-h, --help                      Show this message
	`,
		os.Args[0], f.additionalUsage)

	os.Exit(0)
}
