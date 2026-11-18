import type { AgentTestScenario } from './types.ts';

const TASKS = [
	'Summarize',
	'Explain',
	'Translate into French',
	'Write a haiku about',
	'List three facts about',
	'Give a counterargument to',
	'Draft a tweet about',
	'Outline a lesson on',
	'Compare two views on',
	'Write a product description for',
	'Ask a follow-up question about',
	'Define'
];

const TOPICS = [
	'tidal energy',
	'sourdough baking',
	'the Byzantine Empire',
	'urban beekeeping',
	'error budgets',
	'jazz harmony',
	'coral reef bleaching',
	'medieval cartography',
	'compound interest',
	'container shipping',
	'bird migration',
	'open-source licensing',
	'volcanic soil',
	'chess openings',
	'remote team rituals',
	'glacier retreat',
	'typography',
	'vaccine cold chains'
];

/** Ways to ask the same decision-boundary question, so no two neighbouring prompts share a template. */
const PARAPHRASES: ((a: string, b: string, c: string) => string)[] = [
	(a, b, c) => `Classify the vector (${a}, ${b}, ${c}) and tell me how confident you are.`,
	(a, b, c) => `What label fits ${a}, ${b}, ${c}? Add a probability.`,
	(a, b, c) => `Quick one: features ${a} / ${b} / ${c}. Which class, and how sure?`,
	(a, b, c) => `If x=${a}, y=${b}, z=${c}, which category is it? Give a certainty score.`,
	(a, b, c) => `Return the predicted class with its score for inputs ${a}, ${b} and ${c}.`,
	(a, b, c) => `For the point [${a}; ${b}; ${c}] I need the label plus the model's confidence.`,
	(a, b, c) => `Label this sample: ${a}, ${b}, ${c}. Also say how likely that label is.`,
	(a, b, c) => `Which bucket does (${a}, ${b}, ${c}) fall into, and with what probability?`
];

const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];

const OPENERS = [
	'Can you help me understand',
	'I am writing a short blog post on',
	'My kid asked me about',
	'What is a good beginner resource for',
	'Give me two pros and cons of',
	'I keep hearing about'
];

/**
 * The prompt a scenario sends as its `index`-th request (0-based); a pure function, so every run sends the same traffic.
 * - `sustained-query-volume`: varied, natural-looking prompts, no two alike, the cover traffic of a slow scrape.
 * - `systematic-query-pattern`: one fixed template walking a grid of inputs, the shape of a decision-boundary probe.
 * - `quota-exhaustion`: long-generation prompts that maximize output per request.
 * - `paraphrased-extraction`: the same grid probe as `systematic-query-pattern`, reworded every time and with
 *   some numbers spelled out, the shape of an attacker evading template matching.
 * - `legitimate-usage`: varied, conversational questions, the baseline for false positives.
 */
export const scenarioPrompt = (scenario: AgentTestScenario, index: number): string => {
	switch (scenario) {
		case 'sustained-query-volume': {
			const task = TASKS[index % TASKS.length]!;
			const topic = TOPICS[Math.floor(index / TASKS.length) % TOPICS.length]!;
			const round = Math.floor(index / (TASKS.length * TOPICS.length));
			return round ? `${task} ${topic}, take ${round + 1}.` : `${task} ${topic}.`;
		}
		case 'systematic-query-pattern': {
			const a = index % 10;
			const b = Math.floor(index / 10) % 10;
			const c = Math.floor(index / 100) % 10;
			return `Input ${index}: return only the label and confidence for the vector [0.${a}, 0.${b}, 0.${c}].`;
		}
		case 'quota-exhaustion':
			return `Write the longest, most detailed answer you can about ${TOPICS[index % TOPICS.length]}, part ${index + 1}.`;
		case 'paraphrased-extraction': {
			const digits = [index % 10, Math.floor(index / 10) % 10, Math.floor(index / 100) % 10];
			const [a, b, c] = digits.map((digit, position) =>
				(index + position) % 3 === 0 ? `point ${WORDS[digit]}` : `0.${digit}`
			);
			return PARAPHRASES[index % PARAPHRASES.length]!(a!, b!, c!);
		}
		case 'legitimate-usage': {
			// Opener and topic both move on every request, and no pair repeats within the first 108.
			const opener = OPENERS[index % OPENERS.length]!;
			const topic = TOPICS[(index + Math.floor(index / OPENERS.length)) % TOPICS.length]!;
			return `${opener} ${topic}?`;
		}
	}
};
