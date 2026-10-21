package org.simulationrift.browser

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentDataType
import androidx.compose.ui.semantics.contentDataType
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest

/**
 * Asks the keyboard not to learn from what is typed into [content]'s text
 * fields (`IME_FLAG_NO_PERSONALIZED_LEARNING`, §10.6): addresses, host
 * names and passphrases typed into Rift stay out of the keyboard's
 * dictionary. Keyboards may ignore the flag. The controller and the
 * browser app each have this copy, as they share no Compose code.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun NoPersonalizedLearning(content: @Composable () -> Unit) = InterceptPlatformTextInput(
    interceptor = { request, next ->
        next.startInputMethod(
            object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection =
                    request.createInputConnection(outAttributes).also {
                        outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    }
            },
        )
    },
    content = content,
)

/**
 * Keeps a text field from the autofill framework (§10.7): no autofill
 * service is told about it, fills it or is offered what was typed. The
 * window's own setting (WindowGuard) does not reach Compose's fields,
 * which Compose reports to autofill itself.
 */
fun Modifier.noAutofill(): Modifier = semantics { contentDataType = ContentDataType.None }
