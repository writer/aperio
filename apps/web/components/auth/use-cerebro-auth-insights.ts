"use client";

import { useEffect, useState } from "react";
import {
  CEREBRO_AUTH_INSIGHTS,
  loadCerebroAuthInsights,
  type CerebroAuthInsight
} from "../../lib/cerebro-auth";

type UseCerebroAuthInsightsOptions = {
  loadDiscovery?: boolean;
};

export function useCerebroAuthInsights({
  loadDiscovery = true
}: UseCerebroAuthInsightsOptions = {}) {
  const [sessionInsights, setSessionInsights] =
    useState<readonly CerebroAuthInsight[]>(CEREBRO_AUTH_INSIGHTS);

  useEffect(() => {
    if (!loadDiscovery) {
      setSessionInsights(CEREBRO_AUTH_INSIGHTS);
      return;
    }
    let active = true;
    void loadCerebroAuthInsights().then((insights) => {
      if (active) {
        setSessionInsights(insights);
      }
    });
    return () => {
      active = false;
    };
  }, [loadDiscovery]);

  return sessionInsights;
}
