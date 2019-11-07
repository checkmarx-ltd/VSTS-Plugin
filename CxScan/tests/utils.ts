import {FilePathFilter} from "../services/filePathFilter";
import * as assert from "assert";

export type FilterTestCases = [string, boolean][];

export class Utils {
    static verifyFilterPattern(filterPattern: string, testCases: FilterTestCases) {
        Utils.verifyTestCases(testCases, filterPattern, '');
    }

    static verifyExcludedFolders(excludedFolders: string, testCases: FilterTestCases) {
        Utils.verifyTestCases(testCases, '', excludedFolders);
    }

    private static verifyTestCases(testCases: FilterTestCases, filterPattern: string, excludedFolders: string) {
        const filter = new FilePathFilter(filterPattern, excludedFolders);
        testCases.forEach(pathTestCase => {
            const path = pathTestCase[0];
            const shouldBeIncluded = pathTestCase[1];

            const assertion = shouldBeIncluded ? 'included' : 'excluded';
            const byWhat = filterPattern ? 'filter pattern' : 'excludedFolders';
            const paramToShow = filterPattern || excludedFolders;
            assert.equal(filter.includes(path), shouldBeIncluded, `'${path}' should be ${assertion} by ${byWhat}: '${paramToShow}'`);
        });
    }
}