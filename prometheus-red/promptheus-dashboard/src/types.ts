export interface Session {
  id: string;
  name: string;
  target: string;
  skill: string;
  objective: string;
  model: string;
  status: 'running' | 'success' | 'error' | 'idle';
  created_at: string;
  attempts?: Attempt[];
}

export interface Attempt {
  id: string;
  session_id: string;
  payload: string;
  response: string;
  verdict: Verdict;
  severity: 'Safe' | 'Medium' | 'High';
  created_at: string;
}

export interface Verdict {
  is_vulnerable: boolean;
  reason: string;
  severity: 'low' | 'medium' | 'high';
  heuristics: string[];
  risk_score: number;
  confidence: 'Low' | 'Medium' | 'High';
  category: string;
  mitigation: string;
}

export interface Skill {
  id: string;
  name: string;
  tags: string[];
  description: string;
  template: string;
}

export interface Target {
  id: string;
  name: string;
  type: 'REST' | 'Slack' | 'Local';
  config: {
    url?: string;
    headers?: string;
  };
}
