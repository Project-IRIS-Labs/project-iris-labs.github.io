# IRIS static demo

Project IRIS의 공개 데모 사이트입니다. 실제 Elasticsearch나 Local LLM에 연결하지 않고, DEDALE SET01 평가 결과를 비식별 정적 데이터로 재구성해 보여줍니다.

## 로컬 실행

```bash
python -m http.server 8888
```

브라우저에서 `http://127.0.0.1:8888`에 접속합니다. `file://`로 직접 열면 브라우저 보안 정책 때문에 JSON을 불러오지 못할 수 있습니다.

## 공개 범위

- Sigma 원본 Alert 9건을 그룹화한 조사 사건 6건
- 사건별 AI 판정, 관련 로그 타임라인, HTML 보고서 내보내기
- 룰 최초 Recall과 LLM 후속 증거 범위
- 비밀정보와 서버 연결정보가 없는 정적 스냅샷

실제 탐지·조사 코드는 [IRIS](https://github.com/Project-IRIS-Labs/IRIS), 평가 자료는 [eval-bench](https://github.com/Project-IRIS-Labs/eval-bench)에서 관리합니다.

## 배포

`main` 브랜치의 저장소 루트를 GitHub Pages로 배포합니다. 조직 사이트 주소는 다음과 같습니다.

<https://project-iris-labs.github.io>

## 라이선스

Apache License 2.0
