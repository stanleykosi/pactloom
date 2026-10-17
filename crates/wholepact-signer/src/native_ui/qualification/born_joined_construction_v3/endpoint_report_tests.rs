//! Actual bounded in-process report channels and facade handoff bookkeeping.
//! These tests read this test image's identity but create no socket, native owner,
//! signing key or financial permission. Paths are inert availability metadata.
use super::*;
use std::time::Duration;

#[test]
fn original_report_requires_transfer_and_is_received_once() {
    assert!(OriginalCompletionReportV3::new().unwrap().into_reporter().is_err());
    let mut report = OriginalCompletionReportV3::new().unwrap();
    let provider = report.take_provider().unwrap();
    assert!(report.take_provider().is_err());
    let reporter = report.into_reporter().unwrap();
    let path = Path::new("/synthetic-original-controller/fresh-completion.sock");
    reporter.publish(path).unwrap();
    assert_eq!(provider.wait_native_endpoint(Duration::from_secs(1)).unwrap(), path);
    assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());
    // A locator never makes the current-process provider a production launcher.
    assert!(provider.launch_native().is_err());
}

#[test]
fn missing_or_dropped_report_is_terminal() {
    let (provider, reporter) = InstalledSignerProvider::qualification_current_process_endpoint_pair().unwrap();
    assert!(provider.wait_native_endpoint(Duration::ZERO).is_err());
    assert!(reporter.publish(Path::new("/synthetic/too-late.sock")).is_err());
    assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());

    let (provider, reporter) = InstalledSignerProvider::qualification_current_process_endpoint_pair().unwrap();
    drop(reporter);
    assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());
    assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());
    let unchanged = InstalledSignerProvider::qualification_current_process().unwrap();
    assert!(unchanged.wait_native_endpoint(Duration::from_secs(1)).is_err());
}

#[test]
fn separate_original_report_channels_cannot_supply_each_other() {
    let (first, first_reporter) = InstalledSignerProvider::qualification_current_process_endpoint_pair().unwrap();
    let (second, second_reporter) = InstalledSignerProvider::qualification_current_process_endpoint_pair().unwrap();
    let first_path = Path::new("/synthetic-first/fresh.sock");
    first_reporter.publish(first_path).unwrap();
    // First's queued report cannot satisfy second, even in the same process.
    assert!(second.wait_native_endpoint(Duration::ZERO).is_err());
    assert!(second_reporter.publish(Path::new("/synthetic-second/fresh.sock")).is_err());
    assert_eq!(first.wait_native_endpoint(Duration::from_secs(1)).unwrap(), first_path);
    assert!(first.wait_native_endpoint(Duration::from_secs(1)).is_err());
}

#[test]
fn invalid_report_consumes_the_only_publication_opportunity() {
    for path in [PathBuf::from("relative.sock"), PathBuf::from(format!("/{}", "x".repeat(4096)))] {
        let (provider, reporter) = InstalledSignerProvider::qualification_current_process_endpoint_pair().unwrap();
        assert!(reporter.publish(&path).is_err());
        assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());
        assert!(provider.wait_native_endpoint(Duration::from_secs(1)).is_err());
    }
}
