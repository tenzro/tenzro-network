------------------------------- MODULE MCTdc -------------------------------
(***************************************************************************)
(* The model TLC checks: four validators, one of them Byzantine. A TLC     *)
(* configuration file cannot hold a sequence, so the leader sequence is    *)
(* defined here and substituted for Tdc's LeaderSeq in MCTdc.cfg.          *)
(***************************************************************************)
EXTENDS Tdc

CONSTANTS v1, v2, v3, v4

MCLeaderSeq == <<v1, v2, v4, v3>>

=============================================================================
