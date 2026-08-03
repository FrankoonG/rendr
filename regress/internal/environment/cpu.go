package environment

import (
	"errors"
	"sort"
	"strings"
)

func parseCPUModels(contents []byte) ([]string, error) {
	unique := make(map[string]bool)
	for _, line := range strings.Split(string(contents), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "model name" {
			continue
		}
		model := normalizeValue(parts[1])
		if model != "" {
			unique[model] = true
		}
	}
	if len(unique) == 0 {
		return nil, errors.New("read CPU model inventory: model name is missing")
	}
	models := make([]string, 0, len(unique))
	for model := range unique {
		models = append(models, model)
	}
	sort.Strings(models)
	return models, nil
}

func parseProcessAllowedCPUs(contents []byte) (string, error) {
	for _, line := range strings.Split(string(contents), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "Cpus_allowed_list" {
			continue
		}
		value := normalizeValue(parts[1])
		if value == "" {
			break
		}
		return value, nil
	}
	return "", errors.New("read process allowed CPU list: Cpus_allowed_list is missing")
}
