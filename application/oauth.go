/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package application

import (
	"encoding/json"
	"fmt"

	"github.com/provideplatform/ident/common"
)

// OAuthApplicationConfig represents an OAuth client application config
type OAuthApplicationConfig struct {
	Branding     *OAuthApplicationBrandingConfig `json:"branding,omitempty"`
	ClientID     *string                         `json:"client_id,omitempty"`
	ClientSecret *string                         `json:"client_secret,omitempty"`
	Name         *string                         `json:"name,omitempty"`
	RedirectURI  *string                         `json:"redirect_uri,omitempty"`
	// TODO
}

// OAuthApplicationBrandingConfig includes brand assets for the OAuth application
type OAuthApplicationBrandingConfig struct {
	AuthorizeLogoHref *string `json:"authorize_logo_href,omitempty"`
	// TODO
}

// OAuthClientApplication - parse the public OAuth client application configuration; returns an error if
// the underlying Application instance does not have an OAuth client configuration
func (app *Application) OAuthClientApplication() (*OAuthApplicationConfig, error) {
	cfg := app.ParseConfig()
	if oauth, oauthOk := cfg["oauth"].(map[string]interface{}); oauthOk {
		oauthRaw, err := json.Marshal(oauth) // HACK!!!
		if err != nil {
			common.Log.Warningf("failed to unmarshal oauth application params; %s", err.Error())
			return nil, err
		}

		var oauthClientApplication *OAuthApplicationConfig
		err = json.Unmarshal(oauthRaw, &oauthClientApplication)
		if err != nil {
			common.Log.Warningf("failed to unmarshal oauth application params; %s", err.Error())
			return nil, err
		}

		oauthClientApplication.ClientID = common.StringOrNil(app.ID.String())
		oauthClientApplication.ClientSecret = nil // this should never actually be populated here; just feels right to do this anyway...

		return oauthClientApplication, nil
	}
	return nil, fmt.Errorf("no oauth application configured for ident application: %s", app.ID)
}
