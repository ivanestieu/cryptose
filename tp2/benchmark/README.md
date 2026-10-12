# TP2 : projet de départ du benchmark ESP32

Squelette étudiant du benchmark natif ESP-IDF. Il compile, démarre sur la carte et
parle le format attendu par les outils ; le sujet (PDF) fait foi pour tout le reste.

## Ce que vous écrivez

Quatre fichiers, et seulement eux : à la correction, tout le reste est remplacé par la
version officielle.

1. `main/statistics.c` : les statistiques d'une série ;
2. `main/crypto_cases.c` : six cas PSA, sept avec le profil ChaCha (SHA-256 est fourni
   en exemple complet) ;
3. `main/measure.c` : la fenêtre de mesure ;
4. `tools/analyze_results.py` : l'agrégation des séries.

## Tests hôtes

Depuis ce répertoire, dans un terminal **sans** ESP-IDF activé :

```bash
tools/run_host_tests.sh
```

Le script lance les tests C et Python dans un environnement propre : un shell ESP-IDF
activé place son propre `ld` et son propre `python3` en tête du `PATH` et casse les deux.
Les tests sont rouges au départ et passent au vert au fil des quatre fichiers.

Ne commitez jamais de capture, de binaire, de clé, de `sdkconfig` effectif ou de
répertoire de compilation.
