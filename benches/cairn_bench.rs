use criterion::{Criterion, criterion_group, criterion_main};
use fastcdc::v2020::FastCDC;

fn bench_cdc_chunker(c: &mut Criterion) {
    let data_1mb = vec![0xABu8; 1024 * 1024];
    let data_10mb = vec![0xCDu8; 10 * 1024 * 1024];

    c.bench_function("cdc_chunk_1mb", |b| {
        b.iter(|| {
            let chunker = FastCDC::new(&data_1mb, 16384, 65536, 262144);
            for chunk in chunker {
                let _ = chunk;
            }
        })
    });

    c.bench_function("cdc_chunk_10mb", |b| {
        b.iter(|| {
            let chunker = FastCDC::new(&data_10mb, 16384, 65536, 262144);
            for chunk in chunker {
                let _ = chunk;
            }
        })
    });
}

fn bench_blake3(c: &mut Criterion) {
    let data_1kb = vec![0x42u8; 1024];
    let data_1mb = vec![0x42u8; 1024 * 1024];

    c.bench_function("blake3_hash_1kb", |b| {
        b.iter(|| {
            blake3::hash(&data_1kb);
        })
    });

    c.bench_function("blake3_hash_1mb", |b| {
        b.iter(|| {
            blake3::hash(&data_1mb);
        })
    });
}

fn bench_zstd(c: &mut Criterion) {
    let data_1mb = vec![0xABu8; 1024 * 1024];

    c.bench_function("zstd_compress_1mb", |b| {
        b.iter(|| {
            zstd::stream::encode_all(std::io::Cursor::new(&data_1mb), 3).unwrap();
        })
    });

    let compressed = zstd::stream::encode_all(std::io::Cursor::new(&data_1mb), 3).unwrap();
    c.bench_function("zstd_decompress_1mb", |b| {
        b.iter(|| {
            zstd::stream::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        })
    });
}

fn bench_lz4(c: &mut Criterion) {
    let data_1mb = vec![0xABu8; 1024 * 1024];

    c.bench_function("lz4_compress_1mb", |b| {
        b.iter(|| {
            lz4_flex::compress_prepend_size(&data_1mb);
        })
    });

    let compressed = lz4_flex::compress_prepend_size(&data_1mb);
    c.bench_function("lz4_decompress_1mb", |b| {
        b.iter(|| {
            lz4_flex::decompress_size_prepended(&compressed).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_cdc_chunker,
    bench_blake3,
    bench_zstd,
    bench_lz4,
);
criterion_main!(benches);
