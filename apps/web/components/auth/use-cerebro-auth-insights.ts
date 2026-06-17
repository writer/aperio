"use client";

import { useEffect, useState } from "react";
import {
  CEREBRO_AUTH_INSIGHTS,
  loadCerebroAuthInsights,
  type CerebroAuthInsight
} from "../../lib/cerebro-auth";

export function useCerebroAuthInsights() {
  const [sessionInsights, setSessionInsights] =
    useState<readonly CerebroAuthInsight[]>(CEREBRO_AUTH_INSIGHTS);

  useEffect(() => {
    let active = true;
    void loadCerebroAuthInsights().then((insights) => {
      if (active) {
        setSessionInsights(insights);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  return sessionInsights;
}
