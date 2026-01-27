package main

import (
	"regexp"
	"strings"
)

// validateCVEID checks if the input matches the CVE ID format
func validateCVEID(cveID string) bool {
	// CVE ID format: CVE-YYYY-NNNN (where YYYY is year and NNNN is 4+ digits)
	matched, _ := regexp.MatchString(`^CVE-\d{4}-\d{4,}$`, cveID)
	return matched
}

// sanitizeDiscordContent escapes potentially malicious Discord markdown
func sanitizeDiscordContent(content string) string {
	// Prevent mass mentions and user pings
	replacer := strings.NewReplacer(
		"@everyone", "@\u200beveryone",
		"@here", "@\u200bhere",
		"<@", "<\u200b@",
		"<#", "<\u200b#",
		"<@&", "<\u200b@&",
	)
	return replacer.Replace(content)
}
