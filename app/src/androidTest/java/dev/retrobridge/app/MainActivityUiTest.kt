package dev.retrobridge.app

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityUiTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun appListDescribesBoundedNativeSupportAndOffersApkImport() {
        composeRule.onNodeWithText("Selected ARM32 native execution only").assertIsDisplayed()
        composeRule.onNodeWithText("Import APK").assertIsDisplayed().assertHasClickAction()
        composeRule.onAllNodesWithText("Guest APK launch is not implemented").assertCountEquals(0)
    }
}
