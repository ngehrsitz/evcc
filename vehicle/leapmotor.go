package vehicle

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/evcc-io/evcc/api"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/vehicle/leapmotor"
)

// Leapmotor is an api.Vehicle implementation for Leapmotor cars.
type Leapmotor struct {
	*embed
	*leapmotor.Provider
}

func init() {
	registry.Add("leapmotor", NewLeapmotorFromConfig)
}

// NewLeapmotorFromConfig creates a new Leapmotor vehicle from config.
func NewLeapmotorFromConfig(other map[string]any) (api.Vehicle, error) {
	cc := struct {
		embed               `mapstructure:",squash"`
		User, Password, VIN string
		AppCert, AppKey     string
		Cache               time.Duration
	}{
		Cache: interval,
	}

	if err := util.DecodeOther(other, &cc); err != nil {
		return nil, err
	}

	if cc.User == "" || cc.Password == "" {
		return nil, api.ErrMissingCredentials
	}
	if cc.AppCert == "" || cc.AppKey == "" {
		return nil, fmt.Errorf("leapmotor: appCert and appKey are required (base64-encoded PEM data)")
	}

	certPEM, err := base64.StdEncoding.DecodeString(cc.AppCert)
	if err != nil {
		return nil, fmt.Errorf("leapmotor: decode appCert: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(cc.AppKey)
	if err != nil {
		return nil, fmt.Errorf("leapmotor: decode appKey: %w", err)
	}

	log := util.NewLogger("leapmotor").Redact(cc.User, cc.Password, cc.VIN)

	identity, err := leapmotor.NewIdentity(log, certPEM, keyPEM, cc.User, cc.Password)
	if err != nil {
		return nil, err
	}
	if err := identity.Login(); err != nil {
		return nil, err
	}

	api := leapmotor.NewAPI(log, identity)

	vehicles, err := api.Vehicles()
	if err != nil {
		return nil, fmt.Errorf("leapmotor: get vehicles: %w", err)
	}
	if len(vehicles) == 0 {
		return nil, fmt.Errorf("leapmotor: no vehicles found on account")
	}

	var matched *leapmotor.Vehicle
	for i := range vehicles {
		v := &vehicles[i]
		if cc.VIN == "" || v.VIN == cc.VIN {
			matched = v
			break
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("leapmotor: VIN %s not found on account", cc.VIN)
	}

	return &Leapmotor{
		embed:    &cc.embed,
		Provider: leapmotor.NewProvider(api, matched.VIN, matched.CarType, cc.Cache),
	}, nil
}
