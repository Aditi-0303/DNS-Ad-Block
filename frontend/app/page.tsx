"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Activity } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface ShapItem {
  feature: string;
  value: number;
  shap_value: number;
  impact: "malicious" | "benign";
  reason: string;
}

interface DnsLog {
  id: number;
  domain: string;
  prediction: string;
  score: number;
  explanation: string;
  block_reason?: string;
  created_at: string;
  is_blocked: boolean;
  category: string;
  false_positive_risk: "low" | "medium" | "high";
  impact_summary: string;

  // ML information
  ml_probability?: number;
  ml_decision?: "BLOCK" | "ALLOW";
  ml_threshold?: number;


  // Domain-only ML information
domain_only_ml_probability?: number;
domain_only_ml_decision?: "SUSPICIOUS" | "LOW_RISK";
domain_only_ml_threshold?: number;
domain_only_ml_suspicious?: boolean;

  // SHAP can arrive as either an array or JSON string
  shap_summary?: ShapItem[] | string;
}

/**
 * Converts SHAP data from the backend
 * into a consistent ShapItem[] format.
 */
function getShapItems(
  shapSummary: ShapItem[] | string | undefined
): ShapItem[] {
  if (!shapSummary) {
    return [];
  }

  if (Array.isArray(shapSummary)) {
    return shapSummary;
  }

  try {
    const parsed = JSON.parse(shapSummary);

    return Array.isArray(parsed)
      ? (parsed as ShapItem[])
      : [];
  } catch {
    return [];
  }
}

export default function Dashboard() {
  const [logs, setLogs] = useState<DnsLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await fetch(
          "http://localhost:8000/logs"
        );

        if (response.ok) {
          const data = await response.json();

          setLogs(data);
          setApiError(null);
        } else {
          setApiError(
            `The backend returned ${response.status}.`
          );
        }
      } catch {
        setApiError(
          "The backend at localhost:8000 is unavailable. Start the FastAPI service to receive live Pi-hole data."
        );
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();

    const interval = setInterval(fetchLogs, 5000);

    return () => clearInterval(interval);
  }, []);

  /*
   * Allowed vs blocked traffic
   */
  const pieData = useMemo(() => {
    const blocked = logs.filter(
      (log) => log.is_blocked
    ).length;

    const allowed = logs.length - blocked;

    return [
      {
        name: "Allowed",
        value: allowed,
        color: "#10b981",
      },
      {
        name: "Blocked",
        value: blocked,
        color: "#f43f5e",
      },
    ];
  }, [logs]);

  /*
   * Blocked traffic categories
   */
  const barData = useMemo(() => {
    const counts: Record<string, number> = {};

    logs.forEach((log) => {
      if (log.is_blocked) {
        const category = log.category || "unknown";

        counts[category] =
          (counts[category] || 0) + 1;
      }
    });

    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        count,
      }))
      .slice(0, 5);
  }, [logs]);

  const blockedCount = logs.filter(
    (log) => log.is_blocked
  ).length;

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-6 bg-[#020617] min-h-screen text-slate-100 font-sans">

      {/* =====================================================
          1. TOP STATS BAR
      ====================================================== */}

      <header className="flex flex-wrap items-center justify-between bg-[#0f172a]/50 p-4 rounded-2xl border border-slate-800 shadow-xl">

        <div className="flex items-center gap-4">

          <div className="bg-blue-500/20 p-2 rounded-lg">
            <Activity
              className="text-blue-400"
              size={24}
            />
          </div>

          <div>
            <h1 className="text-lg font-black tracking-tight leading-none uppercase text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400">
              Ad Blocker // AI
            </h1>

            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-1">
              AI-Powered Command Center
            </p>
          </div>

        </div>

        <div className="flex gap-8 px-6 border-x border-slate-800">

          <HeaderItem
            label="Total Queries"
            value={logs.length}
          />

          <HeaderItem
            label="Block Rate"
            value={`${(
              (blockedCount / (logs.length || 1)) *
              100
            ).toFixed(1)}%`}
            color="text-rose-500"
          />

          <HeaderItem
            label="Allowed Rate"
            value={`${(
              ((logs.length - blockedCount) /
                (logs.length || 1)) *
              100
            ).toFixed(1)}%`}
            color="text-emerald-500"
          />

        </div>

        <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-full text-[10px] font-black text-emerald-500 uppercase tracking-widest">

          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>

          System Active

        </div>

      </header>


      {/* =====================================================
          API ERROR
      ====================================================== */}

      {apiError && (
        <div
          role="status"
          className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs font-semibold text-amber-200"
        >
          <span className="font-black uppercase tracking-wider text-amber-400">
            Demo mode:
          </span>{" "}
          {apiError}
        </div>
      )}


      {/* =====================================================
          2. ANALYTICS GRID
      ====================================================== */}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* PIE CHART */}

        <div className="bg-[#0f172a]/50 border border-slate-800 rounded-3xl p-6 shadow-2xl h-[350px]">

          <h2 className="text-xs font-black uppercase tracking-widest text-slate-500 mb-6">
            Pi-hole Decision Distribution
          </h2>

          <ResponsiveContainer
            width="100%"
            height="100%"
          >
            <PieChart>

              <Pie
                data={pieData}
                innerRadius={70}
                outerRadius={90}
                paddingAngle={8}
                dataKey="value"
                stroke="none"
              >
                {pieData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={entry.color}
                  />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  border: "none",
                  borderRadius: "12px",
                  color: "#fff",
                }}
              />

            </PieChart>
          </ResponsiveContainer>

        </div>


        {/* BAR CHART */}

        <div className="bg-[#0f172a]/50 border border-slate-800 rounded-3xl p-6 shadow-2xl h-[350px]">

          <h2 className="text-xs font-black uppercase tracking-widest text-slate-500 mb-6">
            Blocked Traffic Categories
          </h2>

          {barData.length > 0 ? (

            <ResponsiveContainer
              width="100%"
              height="100%"
            >
              <BarChart
                data={barData}
                layout="vertical"
                margin={{
                  left: 40,
                  right: 40,
                }}
              >

                <XAxis
                  type="number"
                  hide
                />

                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="#64748b"
                  fontSize={10}
                  width={100}
                />

                <Tooltip
                  cursor={{
                    fill: "#1e293b",
                  }}
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "none",
                    borderRadius: "12px",
                  }}
                />

                <Bar
                  dataKey="count"
                  fill="#3b82f6"
                  radius={[0, 4, 4, 0]}
                  barSize={20}
                />

              </BarChart>
            </ResponsiveContainer>

          ) : (

            <div className="h-full flex items-center justify-center text-slate-600 text-[10px] uppercase font-bold tracking-widest italic">
              No Pi-hole Blocks Logged
            </div>

          )}

        </div>

      </div>


      {/* =====================================================
          3. WALL OF LOGS
      ====================================================== */}

      <div className="bg-[#0f172a]/50 border border-slate-800 rounded-3xl overflow-hidden shadow-2xl">

        <div className="px-6 py-4 border-b border-slate-800 bg-[#0f172a]/50 flex justify-between items-center">

          <h2 className="text-xs font-black uppercase tracking-widest text-slate-400">
            Wall of Logs // Live Feed
          </h2>

          <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">
            Updating via Real-time Sync
          </span>

        </div>


        <div className="overflow-x-auto max-h-[500px]">

          <table className="w-full text-left text-[11px] border-collapse">

            <thead className="bg-slate-950/80 sticky top-0 z-10 text-slate-500 border-b border-slate-800 font-black uppercase">

              <tr>

                <th className="px-6 py-4 min-w-[220px]">
                  Domain
                </th>

                <th className="px-6 py-4 min-w-[120px]">
                  Pi-hole Decision
                </th>

                <th className="px-6 py-4 min-w-[100px]">
                  Category
                </th>

                <th className="px-6 py-4 min-w-[350px]">
                  Explainable Reason
                </th>

                <th className="px-6 py-4 min-w-[130px]">
                  False Positive Risk
                </th>

                <th className="px-6 py-4 min-w-[100px]">
                  Time
                </th>

              </tr>

            </thead>


            <tbody className="divide-y divide-slate-800/50">

              {loading && logs.length === 0 ? (

                <tr>

                  <td
                    colSpan={6}
                    className="px-6 py-10 text-center text-slate-600 uppercase font-bold tracking-widest"
                  >
                    Loading DNS logs...
                  </td>

                </tr>

              ) : logs.length === 0 ? (

                <tr>

                  <td
                    colSpan={6}
                    className="px-6 py-10 text-center text-slate-600 uppercase font-bold tracking-widest"
                  >
                    No DNS logs available
                  </td>

                </tr>

              ) : (

                logs.map((log) => {

                  const shapItems =
                    getShapItems(log.shap_summary);

                  return (

                    <tr
                      key={log.id}
                      className="hover:bg-slate-800/20 transition-all group"
                    >

                      {/* =================================================
                          DOMAIN
                      ================================================== */}

                      <td className="px-6 py-3 align-top font-bold text-slate-300 group-hover:text-blue-400">

                        <div
                          className="max-w-[220px] truncate"
                          title={log.domain}
                        >
                          {log.domain}
                        </div>

                      </td>


                      {/* =================================================
                          PI-HOLE / ML DECISION
                      ================================================== */}

                      <td className="px-6 py-3 align-top">

                        <div className="flex flex-col gap-1 items-start">

                          <span
                            className={`px-2 py-0.5 rounded-[4px] font-black tracking-tighter ${
                              log.is_blocked
                                ? "bg-rose-500/20 text-rose-500 border border-rose-500/30"
                                : "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                            }`}
                          >
                            {log.is_blocked
                              ? "BLOCKED"
                              : "ALLOWED"}
                          </span>

                          {log.ml_probability !==
                            undefined && (

                            <span className="text-[9px] text-slate-500 font-mono">

                              ML:{" "}
                              {(
                                log.ml_probability * 100
                              ).toFixed(2)}
                              %
                              {log.domain_only_ml_probability !==
  undefined && (
  <span
    className={`text-[9px] font-black ${
      log.domain_only_ml_suspicious
        ? "text-rose-400"
        : "text-emerald-400"
    }`}
  >
     RISK:{" "}
    {log.domain_only_ml_decision}{" "}
    (
    {(
      log.domain_only_ml_probability *
      100
    ).toFixed(2)}
    %)
  </span>
)}


                            </span>

                          )}

                        </div>

                      </td>


                      {/* =================================================
                          CATEGORY
                      ================================================== */}

                      <td className="px-6 py-3 align-top font-mono text-slate-500 uppercase">

                        {log.category ||
                          "unknown"}

                      </td>


                      {/* =================================================
                          EXPLAINABLE REASON + SHAP
                      ================================================== */}

                      <td className="px-6 py-3 align-top text-slate-400 max-w-[400px]">

                        <div className="max-w-[400px]">

                          {/* Human-readable reason */}

                          <div
                            className="truncate"
                            title={
                              log.is_blocked &&
                              log.block_reason
                                ? log.block_reason
                                : log.explanation
                            }
                          >

                            {log.is_blocked &&
                            log.block_reason
                              ? log.block_reason
                              : log.explanation}

                          </div>


                          {/* SHAP DETAILS */}

                          {log.is_blocked &&
                            shapItems.length > 0 && (

                              <details className="mt-1">

                                <summary className="cursor-pointer text-[9px] font-black uppercase tracking-wider text-blue-400 hover:text-blue-300">

                                  ▶ View XAI Details

                                </summary>


                                <div className="mt-2 space-y-1 border-l border-slate-700 pl-2">

                                  {shapItems
                                    .slice(0, 5)
                                    .map(
                                      (
                                        item,
                                        index
                                      ) => (

                                        <div
                                          key={`${item.feature}-${index}`}
                                          className="text-[9px]"
                                        >

                                          <span className="font-bold text-slate-300">

                                            {
                                              item.feature
                                            }

                                          </span>

                                          <span className="text-slate-500">

                                            {" "}
                                            (
                                            {Number(
                                              item.value
                                            ).toFixed(
                                              3
                                            )}
                                            )

                                          </span>

                                          <span
                                            className={
                                              item.impact ===
                                              "malicious"
                                                ? "text-rose-400"
                                                : "text-emerald-400"
                                            }
                                          >

                                            {" "}
                                            •{" "}
                                            {
                                              item.impact
                                            }

                                          </span>

                                          {item.reason && (

                                            <div className="mt-0.5 text-slate-500">

                                              {
                                                item.reason
                                              }

                                            </div>

                                          )}

                                        </div>

                                      )
                                    )}

                                </div>

                              </details>

                            )}

                        </div>

                      </td>


                      {/* =================================================
                          FALSE POSITIVE RISK
                      ================================================== */}

                      <td
                        className={`px-6 py-3 align-top font-black uppercase ${
                          log.false_positive_risk ===
                          "high"
                            ? "text-amber-400"
                            : log.false_positive_risk ===
                              "medium"
                            ? "text-blue-400"
                            : "text-emerald-400"
                        }`}
                      >

                        {log.false_positive_risk}

                      </td>


                      {/* =================================================
                          TIME
                      ================================================== */}

                      <td className="px-6 py-3 align-top text-slate-600 font-mono whitespace-nowrap">

                        {new Date(
                          log.created_at
                        ).toLocaleTimeString()}

                      </td>

                    </tr>

                  );

                })

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  );
}


/* =========================================================
   HEADER METRIC
========================================================= */

function HeaderItem({
  label,
  value,
  color = "text-slate-200",
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="text-center">

      <p className="text-[9px] font-black uppercase tracking-widest text-slate-500 mb-1">
        {label}
      </p>

      <p className={`text-sm font-black ${color}`}>
        {value}
      </p>

    </div>
  );
}