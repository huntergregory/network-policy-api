# KubeCon EU 2024 Demo

Forked from [upstream](https://github.com/kubernetes-sigs/network-policy-api/) for demo purposes. Click [here](https://github.com/kubernetes-sigs/network-policy-api/issues/150) for the Policy Assistant parent issue.

Feel free to clone this code and modify YAMLs to experiment with different policies.

```shell
policy-assistant analyze --policy-path demo/ --mode probe,explain,verdict
```

```shell
simulated connectivity:
+--------+--------+--------+
| TCP/80 | DEMO/A | DEMO/B |
| TCP/81 |        |        |
+--------+--------+--------+
| demo/a | . X    | . X    |
+--------+--------+--------+
| demo/b | . X    | . X    |
+--------+--------+--------+

explained policies:
+---------+---------------------------------------+---------------------------+------------+----------------------------+--------------------------+
|  TYPE   |                SUBJECT                |       SOURCE RULES        |    PEER    |           ACTION           |      PORT/PROTOCOL       |
+---------+---------------------------------------+---------------------------+------------+----------------------------+--------------------------+
| Ingress | Namespace:                            | [NPv1] demo/deny-to-pod-a | none       | NPv1:                      | none                     |
|         |    demo                               |                           |            |    Allow any peers         |                          |
|         | Pod:                                  |                           |            |                            |                          |
|         |    pod = a                            |                           |            |                            |                          |
+         +---------------------------------------+---------------------------+------------+----------------------------+--------------------------+
|         | Namespace:                            | [ANP] default/anp1        | Namespace: | BANP:                      | all ports, all protocols |
|         |    kubernetes.io/metadata.name = demo | [ANP] default/anp2        |    all     |    Deny                    |                          |
|         |                                       | [ANP] default/anp3        | Pod:       |                            |                          |
|         |                                       | [BANP] default/default    |    all     |                            |                          |
+         +                                       +                           +            +----------------------------+--------------------------+
|         |                                       |                           |            | ANP:                       | port 80 on TCP           |
|         |                                       |                           |            |    pri=1 (allow-80): Allow |                          |
|         |                                       |                           |            |                            |                          |
|         |                                       |                           |            |                            |                          |
+         +                                       +                           +            +----------------------------+--------------------------+
|         |                                       |                           |            | ANP:                       | port 81 on TCP           |
|         |                                       |                           |            |    pri=2 (pass-81): Pass   |                          |
|         |                                       |                           |            |    pri=3 (deny-81): Deny   |                          |
|         |                                       |                           |            |                            |                          |
+---------+---------------------------------------+---------------------------+------------+----------------------------+--------------------------+

verdict walkthrough:
+---------------------------+---------+--------------------------------------------------------+------------------------------+
|          TRAFFIC          | VERDICT |                  INGRESS WALKTHROUGH                   |      EGRESS WALKTHROUGH      |
+---------------------------+---------+--------------------------------------------------------+------------------------------+
| demo/a -> demo/b:80 (TCP) | Allowed | [ANP] Allow (allow-80)                                 | no policies targeting egress |
+---------------------------+---------+--------------------------------------------------------+                              +
| demo/a -> demo/b:81 (TCP) | Denied  | [ANP] Pass (pass-81) -> [BANP] Deny (baseline-deny)    |                              |
+---------------------------+---------+--------------------------------------------------------+                              +
| demo/b -> demo/a:80 (TCP) | Allowed | [ANP] Allow (allow-80)                                 |                              |
+---------------------------+---------+--------------------------------------------------------+                              +
| demo/b -> demo/a:81 (TCP) | Denied  | [ANP] Pass (pass-81) -> [NPv1] Dropped (deny-to-pod-a) |                              |
+---------------------------+---------+--------------------------------------------------------+------------------------------+
```

## Quick Setup

Requirements:
- Docker
- Go 1.21

```shell
# start docker then run these commands in the cmd/policy-assistant/ directory:
make cyclonus
mv cmd/cyclonus/cyclonus ./policy-assistant
./policy-assistant analyze --policy-path demo/ --mode probe
```

The options for `--mode` are:
- `probe`
- `explain`
- `verdict`

## Changing Policies

Place ANPs in `<policy-path>/anp/`, NetworkPolicies in `<policy-path>/npv1/`, and the BANP in `<policy-path>/banp/banp.yaml`.

## Changing Pods

The Pods are hard-coded, but eventually the tool will use your cluster's Pods or a JSON configuration.

See these code comments for where to change hard-coded Pods:

```
// FIXME: use actual cluster pods
```

and

```
// FIXME: use pod resources from CLI arguments or JSON
```
