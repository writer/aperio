package bootstrap

import (
	"net/url"
	"sort"
	"strings"

	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/cerebroclient"
)

func (a *App) WithCerebroSourceID(sourceID string) *App {
	a.cerebroSourceID = strings.TrimSpace(sourceID)
	return a
}

func (a *App) WithCerebroWebURL(webURL string) *App {
	a.cerebroWebURL = normalizeAbsoluteURL(webURL)
	return a
}

func (a *App) findingCerebroWebLinks(findingID string, sourceEventID string, rootURNs []string) []*aperiov1.CerebroWebLink {
	links := []*aperiov1.CerebroWebLink{}
	runtimeID := a.cerebroRuntimeIDOrDefault()
	sourceID := a.cerebroSourceIDOrDefault()
	if runtimeID != "" && sourceID != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Source runtime", "runtime", "/connectors/"+url.PathEscape(sourceID), map[string]string{
			"runtime_id": runtimeID,
			"tab":        "connections",
		}))
	}
	if query := firstString(sourceEventID, findingID); query != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Risk inbox match", "finding-search", "/risk-inbox", map[string]string{
			"runtime_id": runtimeID,
			"source_id":  sourceID,
			"q":          query,
		}))
	}
	rootURN := firstNonEmptyFromSlice(rootURNs)
	if rootURN == "" {
		return links
	}
	if cerebroFindingID := cerebroFindingIDFromURN(rootURN); cerebroFindingID != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Cerebro finding", "finding", "/findings/"+url.PathEscape(cerebroFindingID), nil))
	}
	links = appendCerebroRootWebLinks(links, a, rootURN, "Why is "+shortCerebroURN(rootURN)+" risky and which entities are affected?")
	return links
}

func (a *App) incidentCerebroWebLinks(incidentID string, sourceEventIDs []string, rootURNs []string) []*aperiov1.CerebroWebLink {
	links := []*aperiov1.CerebroWebLink{}
	runtimeID := a.cerebroRuntimeIDOrDefault()
	sourceID := a.cerebroSourceIDOrDefault()
	if runtimeID != "" && sourceID != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Source runtime", "runtime", "/connectors/"+url.PathEscape(sourceID), map[string]string{
			"runtime_id": runtimeID,
			"tab":        "connections",
		}))
	}
	if query := firstString(firstNonEmptyFromSlice(sourceEventIDs), incidentID); query != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Risk inbox", "finding-search", "/risk-inbox", map[string]string{
			"runtime_id": runtimeID,
			"source_id":  sourceID,
			"q":          query,
		}))
	}
	if rootURN := firstNonEmptyFromSlice(rootURNs); rootURN != "" {
		links = appendCerebroRootWebLinks(links, a, rootURN, "Summarize this incident's affected entities, evidence, and likely blast radius.")
	}
	return links
}

func (a *App) securityCerebroWebLinks(rootURNs []string) []*aperiov1.CerebroWebLink {
	links := []*aperiov1.CerebroWebLink{}
	runtimeID := a.cerebroRuntimeIDOrDefault()
	sourceID := a.cerebroSourceIDOrDefault()
	if runtimeID != "" && sourceID != "" {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Source runtime", "runtime", "/connectors/"+url.PathEscape(sourceID), map[string]string{
			"runtime_id": runtimeID,
			"tab":        "connections",
		}))
	}
	links = appendCerebroWebLink(links, a.cerebroWebLink("Risk inbox", "risk-inbox", "/risk-inbox", map[string]string{
		"runtime_id": runtimeID,
		"source_id":  sourceID,
	}))
	if rootURN := firstNonEmptyFromSlice(rootURNs); rootURN != "" {
		links = appendCerebroRootWebLinks(links, a, rootURN, "Which high-risk paths depend on this security context?")
	} else {
		links = appendCerebroWebLink(links, a.cerebroWebLink("Ask graph", "ask", "/ask", map[string]string{
			"q": "Which high-risk SaaS paths should we investigate first?",
		}))
	}
	return links
}

func appendCerebroRootWebLinks(links []*aperiov1.CerebroWebLink, a *App, rootURN string, question string) []*aperiov1.CerebroWebLink {
	links = appendCerebroWebLink(links, a.cerebroWebLink("Evidence", "evidence", "/evidence", map[string]string{"graph_root_urn": rootURN}))
	links = appendCerebroWebLink(links, a.cerebroWebLink("Impact map", "impact", "/impact", map[string]string{"root_urn": rootURN}))
	links = appendCerebroWebLink(links, a.cerebroWebLink("Explore graph", "explore", "/explore", map[string]string{"root_urn": rootURN}))
	links = appendCerebroWebLink(links, a.cerebroWebLink("Ask graph", "ask", "/ask", map[string]string{
		"q":         question,
		"scope_urn": rootURN,
	}))
	return links
}

func (a *App) addCerebroEntityWebURLs(items []map[string]any) []map[string]any {
	for _, item := range items {
		urn := stringFromAny(item["urn"])
		if webURL := a.cerebroEntityWebURL(urn); webURL != "" {
			item["webUrl"] = webURL
		}
	}
	return items
}

func (a *App) addCerebroGraphPathWebURLs(paths []map[string]any) []map[string]any {
	for _, path := range paths {
		nodes := anyList(path["nodes"])
		for _, rawNode := range nodes {
			urn := stringFromAny(asMap(rawNode)["urn"])
			if webURL := a.cerebroExploreWebURL(urn); webURL != "" {
				path["webUrl"] = webURL
				break
			}
		}
	}
	return paths
}

func (a *App) cerebroEntityWebURL(urn string) string {
	_, webURL := a.cerebroWebRoute("/impact", map[string]string{"root_urn": strings.TrimSpace(urn)})
	return webURL
}

func (a *App) cerebroExploreWebURL(urn string) string {
	_, webURL := a.cerebroWebRoute("/explore", map[string]string{"root_urn": strings.TrimSpace(urn)})
	return webURL
}

func (a *App) cerebroWebLink(label string, kind string, path string, params map[string]string) *aperiov1.CerebroWebLink {
	route, webURL := a.cerebroWebRoute(path, params)
	if webURL == "" {
		return nil
	}
	return &aperiov1.CerebroWebLink{
		Label: label,
		Kind:  kind,
		Route: route,
		Url:   webURL,
	}
}

func (a *App) cerebroWebRoute(path string, params map[string]string) (string, string) {
	if a == nil {
		return "", ""
	}
	base := normalizeAbsoluteURL(a.cerebroWebURL)
	if base == "" {
		return "", ""
	}
	route := strings.TrimSpace(path)
	if route == "" {
		route = "/"
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if len(params) > 0 {
		query := url.Values{}
		keys := make([]string, 0, len(params))
		for key := range params {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if value := strings.TrimSpace(params[key]); value != "" {
				query.Set(key, value)
			}
		}
		if encoded := query.Encode(); encoded != "" {
			route += "?" + encoded
		}
	}
	return route, strings.TrimRight(base, "/") + route
}

func appendCerebroWebLink(links []*aperiov1.CerebroWebLink, link *aperiov1.CerebroWebLink) []*aperiov1.CerebroWebLink {
	if link == nil || strings.TrimSpace(link.Url) == "" {
		return links
	}
	for _, existing := range links {
		if existing.GetUrl() == link.GetUrl() {
			return links
		}
	}
	return append(links, link)
}

func cerebroWebLinksToMaps(links []*aperiov1.CerebroWebLink) []map[string]string {
	out := make([]map[string]string, 0, len(links))
	for _, link := range links {
		if link == nil || strings.TrimSpace(link.Url) == "" {
			continue
		}
		out = append(out, map[string]string{
			"label": link.GetLabel(),
			"url":   link.GetUrl(),
			"route": link.GetRoute(),
			"kind":  link.GetKind(),
		})
	}
	return out
}

func (a *App) cerebroRuntimeIDOrDefault() string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.cerebroRuntimeID)
}

func (a *App) cerebroSourceIDOrDefault() string {
	if a == nil {
		return cerebroclient.DefaultSourceID
	}
	if sourceID := strings.TrimSpace(a.cerebroSourceID); sourceID != "" {
		return sourceID
	}
	return cerebroclient.DefaultSourceID
}

func firstNonEmptyFromSlice(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sourceEventIDsFromFindings(findings []findingRow) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, finding := range findings {
		sourceEventID := strings.TrimSpace(stringFromAny(finding.Evidence["sourceEventId"]))
		if sourceEventID == "" {
			continue
		}
		if _, ok := seen[sourceEventID]; ok {
			continue
		}
		seen[sourceEventID] = struct{}{}
		out = append(out, sourceEventID)
	}
	return out
}

func cerebroFindingIDFromURN(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	for i, part := range parts {
		if part == "finding" && i+1 < len(parts) {
			return strings.TrimSpace(parts[i+1])
		}
	}
	return ""
}
