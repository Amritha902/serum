"""Application scenarios that specialise SERUM to a real threat model.

Each scenario builds a topology + vulnerability profile + payload + criticality
already wired for a specific incident class (Mirai-style IoT DDoS, enterprise
ransomware, ...). Everything else in ``serum`` stays payload-generic; the
scenarios only choose *how* the generic pieces are configured.
"""
