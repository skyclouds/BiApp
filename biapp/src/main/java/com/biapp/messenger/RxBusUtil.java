package com.biapp.messenger;

import io.reactivex.functions.Consumer;
import io.reactivex.subscribers.DisposableSubscriber;
import com.biapp.messenger.interfaces.IRxBusQueue;
import com.biapp.messenger.rx.RxUtil;

/**
 * Created by flisar on 02.05.2016.
 */
public class RxBusUtil {
    protected static <T> Consumer<T> wrapQueueConsumer(Consumer<T> action, IRxBusQueue isResumedProvider) {
        return t -> {
            if (RxUtil.safetyQueueCheck(t, isResumedProvider))
                action.accept(t);
        };
    }

    protected static <T> DisposableSubscriber<T> wrapSubscriber(DisposableSubscriber<T> subscriber, IRxBusQueue isResumedProvider) {
        return new DisposableSubscriber<T>() {
            @Override
            public void onComplete() {
                subscriber.onComplete();
            }

            @Override
            public void onError(Throwable e) {
                subscriber.onError(e);
            }

            @Override
            public void onNext(T t) {
                if (RxUtil.safetyQueueCheck(t, isResumedProvider))
                    subscriber.onNext(t);
            }
        };
    }
}
