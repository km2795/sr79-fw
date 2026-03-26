package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	DeviceInterface string  `json:"device_interface"`
	WeightsPath     string  `json:"weights_path"`
	Topology        []int   `json:"topology"`
	Threshold       float64 `json:"threshold"`
	LearningRate    float64 `json:"learning_rate"`
	WebAppUrl       string  `json:"web_app_url"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
