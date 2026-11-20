import XCTest

final class RouterSetupUITests: XCTestCase {
    func testWizardLaunchesWithoutRouterOrCredentials() {
        let app = XCUIApplication()
        app.launch()
        let web = app.webViews.firstMatch
        XCTAssertTrue(web.waitForExistence(timeout: 30))
        let heading = web.descendants(matching: .any)
            .matching(NSPredicate(format: "label == %@", "Подключение к роутеру")).firstMatch
        XCTAssertTrue(heading.waitForExistence(timeout: 15))
        XCTAssertTrue(web.buttons["Проверить роутер"].exists)
    }
}
