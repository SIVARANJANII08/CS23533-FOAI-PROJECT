"""
Module 4: Agent / Orchestration
MITRE ATT&CK Rule-Based Navigator

Owner: Pranathee H

The Agent coordinates the complete reasoning workflow:
observations -> inference -> ranking -> explanation -> results.
"""

try:
    from .inference_engine import ForwardChainingEngine
    from .explanation import ExplanationBuilder
except ImportError:
    from inference_engine import ForwardChainingEngine
    from explanation import ExplanationBuilder

class Agent:
    """
    Coordinates the MITRE ATT&CK reasoning pipeline.
    """

    def __init__(self, knowledge_base):
        self.knowledge_base = knowledge_base
        self.engine = ForwardChainingEngine(knowledge_base)
        self.explainer = None

    def process(self, observations):
        """
        Process observed behaviours through the inference engine.
        """

        self.engine.assert_observations(observations)
        self.engine.run()

        self.explainer = ExplanationBuilder(self.engine)

        return self.engine

    def get_results(self):
        """
        Return the detected techniques in firing order.
        """

        return self.engine.detected_techniques()

    def get_ranked_rules(self):
        """
        Return rules ranked by Module 3 confidence.
        """

        return self.engine.rank_rules()

    def get_explanation(self):
        """
        Return explanations for detected techniques.
        """

        if self.explainer is None:
            return "No inference has been performed yet."

        return self.explainer.explain_all()