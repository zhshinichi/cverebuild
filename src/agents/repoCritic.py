import re

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the setup report in the following specified format.

```
<report>
<analysis>...</analysis>
<decision>...</decision>
<possible></possible>
<feedback>...</feedback>
</report>
```

Within <analysis></analysis>, replace ... with the analysis of the setup.
Within <decision></decision>, replace ... with the decision whether the setup is correct or not, ONLY use "yes" or "no" as the decision.
Within <possible></possible>, replace ... with the decision whether it is possible to correct the setup or not (if the setup is incorrect), ONLY use "yes" or "no" as the decision. (If the setup is correct add "n/a" to this field).
Within <feedback></feedback>, replace ... with feedback on how to correct the setup if it is incorrect (if the setup is correct or it is not possible to improve the setup, add "n/a" to this field).
'''

class MyParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        response = msg.content
        if isinstance(response, list):
            response = ' '.join(response)
        return self.parse(response)
    
    def fix_patch_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        return fixed_text
    
    def _get_tag(self, tag: str, text: str) -> Optional[str]:
        """Helper to extract content from tags with robustness."""
        # Case-insensitive search, handle whitespace, DOTALL for multiline content
        pattern = f'<{tag}>(.*?)</{tag}>'
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else None

    def parse(self, text: str) -> dict:
        try_itr = 1
        raw_text = text
        
        while try_itr <= self.MAX_FIX_FORMAT_TRIES:
            try:
                analysis = self._get_tag('analysis', text)
                decision = self._get_tag('decision', text)
                possible = self._get_tag('possible', text)
                feedback = self._get_tag('feedback', text)

                # Check if any tag is missing
                missing_tags = [t for t, v in [('analysis', analysis), ('decision', decision), 
                                             ('possible', possible), ('feedback', feedback)] if v is None]
                if missing_tags:
                    raise ValueError(f'Missing tags: {", ".join(missing_tags)}')

                # Validate and normalize decision
                decision = decision.lower()
                if 'yes' in decision:
                    decision = 'yes'
                elif 'no' in decision:
                    decision = 'no'
                else:
                    raise ValueError(f'Invalid decision: {decision}')

                # Validate and normalize possible
                possible = possible.lower()
                if 'yes' in possible:
                    possible = 'yes'
                elif 'no' in possible:
                    possible = 'no'
                elif 'n/a' in possible:
                    possible = 'n/a'
                else:
                    possible = 'no' # Default to no if unclear

                print(f"🪖 Critic Response: '''\n{text[:500]}...\n'''")
                print(f'✅ Successfully parsed the output!')
                
                return dict(
                    analysis=analysis,
                    decision=decision,
                    possible=possible,
                    feedback=feedback
                )

            except Exception as e:
                print(f'🤡 Parsing Error: {e}')
                if try_itr < self.MAX_FIX_FORMAT_TRIES:
                    print(f'🤡 Trying to fix the format ... Attempt {try_itr}!!')
                    text = self.fix_patch_format(text)
                try_itr += 1

        # Final Fallback to prevent system crash
        print(f"⚠️ Failed to parse RepoCritic output after {self.MAX_FIX_FORMAT_TRIES} attempts. Using fallback.")
        return dict(
            analysis=f"FAILED_TO_PARSE: {raw_text[:200]}...",
            decision="no",
            possible="yes",
            feedback="The critic's output was malformed and could not be parsed automatically. Please ensure the output follows the <tag> format strictly."
        )

class RepoCritic(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = 'o3'
    __SYSTEM_PROMPT_TEMPLATE__ = 'repoCritic/repoCritic.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'repoCritic/repoCritic.user.j2'
    __OUTPUT_PARSER__ = MyParser

    SETUP_LOGS: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.SETUP_LOGS = kwargs.get('setup_logs')
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            SETUP_LOGS = self.SETUP_LOGS
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
