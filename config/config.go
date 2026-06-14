package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

var loaded *Config

// Load reads the env-specific JSON config (assets/kharchibook/<env>-config.json),
// applies environment-variable overrides, and returns the parsed Config.
//
// The active environment is selected by ACTIVE_ENV (defaults to "dev").
func Load() (*Config, error) {
	env := os.Getenv("ACTIVE_ENV")
	if env == "" {
		env = "dev"
	}

	v := viper.New()
	v.SetConfigName(fmt.Sprintf("%s-config", env))
	v.SetConfigType("json")
	v.AddConfigPath("./assets/kharchibook")
	v.AddConfigPath("../assets/kharchibook")
	v.AddConfigPath("../../assets/kharchibook")

	// Allow env-var overrides, e.g. STORE_PASSWORD overrides store.password.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %q: %w", env, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	cfg.App.Env = env

	loaded = &cfg
	return &cfg, nil
}

// Get returns the previously loaded config. Panics if Load was not called.
func Get() *Config {
	if loaded == nil {
		panic("config.Get called before config.Load")
	}
	return loaded
}
