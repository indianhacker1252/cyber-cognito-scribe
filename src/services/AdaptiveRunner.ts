/**
 * AdaptiveRunner - Iterative Verification Loop
 * Attempts up to 3 adapted variations of a verification test,
 * checking after each if the filter was navigated successfully.
 */

import { classifyFilter, isFiltered, isVerificationSuccess, type FilterAnalysis } from "./HeuristicAnalyst";
import { getAdaptationStrategies, applyAdaptation, type AdaptationStep } from "./AdaptiveStrategy";

export interface AdaptationAttempt {
  iteration: number;
  adaptationApplied: AdaptationStep;
  transformedPayload: string;
  filterAnalysis: FilterAnalysis;
  success: boolean;
  reasoning: string;
}

export interface AdaptiveValidationResult {
  originalPayload: string;
  filterClassification: string;
  attempts: AdaptationAttempt[];
  finalStatus: "verification_success" | "all_filtered" | "error";
  successfulPayload?: string;
  successfulAdaptation?: string;
}

const MAX_ITERATIONS = 3;

/**
 * Runs the adaptive validation loop using AI-simulated responses.
 * In production, this would make real HTTP requests to the target.
 * Here, the AI simulates the responses via the edge function.
 */
export async function runAdaptiveLoop(
  originalPayload: string,
  initialStatusCode: number,
  initialResponseBody: string,
  simulateRequest: (payload: string, adaptationName: string) => Promise<{ statusCode: number; body: string; length: number }>
): Promise<AdaptiveValidationResult> {
  // Step 1: Classify the initial filter
  const initialAnalysis = classifyFilter(initialStatusCode, initialResponseBody);
  const strategies = getAdaptationStrategies(initialAnalysis.classification);

  const attempts: AdaptationAttempt[] = [];
  let prevLength = initialResponseBody.length;

  for (let i = 0; i < Math.min(MAX_ITERATIONS, strategies.length); i++) {
    const strategy = strategies[i];
    const transformedPayload = applyAdaptation(originalPayload, strategy);

    // Simulate the adapted request
    const response = await simulateRequest(transformedPayload, strategy.name);
    const analysis = classifyFilter(response.statusCode, response.body);

    const success = isVerificationSuccess(response.statusCode, prevLength, response.length);

    attempts.push({
      iteration: i + 1,
      adaptationApplied: {
        type: strategy.type,
        name: strategy.name,
        description: strategy.description,
        transform: strategy.transform,
      },
      transformedPayload,
      filterAnalysis: analysis,
      success,
      reasoning: success
        ? `Adaptation "${strategy.name}" successfully navigated the filter. Response changed from blocked to status ${response.statusCode}.`
        : `Adaptation "${strategy.name}" did not navigate the filter. Response still ${response.statusCode}. Proceeding to next strategy.`,
    });

    if (success) {
      return {
        originalPayload,
        filterClassification: initialAnalysis.classification,
        attempts,
        finalStatus: "verification_success",
        successfulPayload: transformedPayload,
        successfulAdaptation: strategy.name,
      };
    }

    prevLength = response.length;
  }

  return {
    originalPayload,
    filterClassification: initialAnalysis.classification,
    attempts,
    finalStatus: "all_filtered",
  };
}
