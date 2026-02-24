use criterion::{black_box, criterion_group, criterion_main, Criterion};
use aegis_core::command_parser::parse_command;
use aegis_core::typosquat::TyposquatDetector;

fn bench_parse_command(c: &mut Criterion) {
    c.bench_function("parse pip install", |b| {
        b.iter(|| parse_command(black_box("pip install requests numpy pandas")))
    });

    c.bench_function("parse npm install", |b| {
        b.iter(|| parse_command(black_box("npm install express lodash react")))
    });

    c.bench_function("parse non-install", |b| {
        b.iter(|| parse_command(black_box("ls -la /tmp")))
    });
}

fn bench_typosquat(c: &mut Criterion) {
    let detector = TyposquatDetector::new(2);

    c.bench_function("typosquat check known", |b| {
        b.iter(|| detector.check(black_box("requests"), "python"))
    });

    c.bench_function("typosquat check typo", |b| {
        b.iter(|| detector.check(black_box("reqeusts"), "python"))
    });

    c.bench_function("typosquat check unknown", |b| {
        b.iter(|| detector.check(black_box("my-custom-internal-pkg"), "python"))
    });
}

criterion_group!(benches, bench_parse_command, bench_typosquat);
criterion_main!(benches);
