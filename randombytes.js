mergeInto(LibraryManager.library, {
  randombytes: function(ptr, nLowBits, nHighBits) {
    rand = window['balboa']['web']['cljs']['crypto']['randombytes'];
    if (nHighBits > 0) {
      throw {name: 'Overflow', message: 'You have requested too many random numbers.'}
    } else {
      HEAPU8.set(rand(nLowBits), ptr);
    }
  }
});
